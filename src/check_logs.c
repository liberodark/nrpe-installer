#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <lzma.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#define BLOCK_SIZE 16384
#define PASSWORD_SALT "Z9h)'%$*"

enum opt_id
{
	OPT_DECRYPT = 0,
	OPT_ENCRYPT,
	OPT_LOG,
	OPT_PATH,
	OPT_THREADS,
	OPT_COUNT
};

enum opt_type
{
	OPT_TYPE_INVAL = 0,
	OPT_TYPE_INT,
	OPT_TYPE_STR
};

struct opt
{
	enum opt_type type;
	const char *name;
	union {
		int as_int;
		const char *as_str;
	} data;
};

int parse_opts(int argc, char **argv, size_t opt_count, struct opt *opts)
{
	int result;

	for (int i = 1; i < argc; i++)
	{
		char *arg = argv[i];
		int matched = 0;

		for (size_t j = 0; j < opt_count; j++)
		{
			struct opt *opt = &opts[j];

			result = strcmp(arg, opt->name);
			if (result != 0)
				continue;

			if (i >= argc - 1)
				return -1;

			matched = 1;
			opt->data.as_str = argv[++i];
		}

		if (!matched)
			return -1;
	}

	for (size_t i = 0; i < opt_count; i++)
	{
		struct opt *opt = &opts[i];

		if (opt->data.as_str)
			continue;

		opt->type = OPT_TYPE_INVAL;
	}

	for (size_t i = 0; i < opt_count; i++)
	{
		struct opt *opt = &opts[i];

		switch (opt->type)
		{
			case OPT_TYPE_INVAL:
				break;

			case OPT_TYPE_INT:
			{
				char *endptr;
				int n;

				if (*opt->data.as_str == '\0')
					return -1;

				n = strtol(opt->data.as_str, &endptr, 0);
				if (*endptr != '\0')
					return -1;

				opt->data.as_int = n;
				break;
			}

			case OPT_TYPE_STR:
				break;
		}
	}

	return 0;
}

int get_opt_defined(struct opt *opts, enum opt_id id)
{
	if (id >= OPT_COUNT)
		return 0;

	return opts[id].type != OPT_TYPE_INVAL;
}

int get_opt_int(struct opt *opts, enum opt_id id)
{
	if (id >= OPT_COUNT)
		return INT_MAX;

	if (opts[id].type != OPT_TYPE_INT)
		return INT_MAX;

	return opts[id].data.as_int;
}

const char *get_opt_str(struct opt *opts, enum opt_id id)
{
	if (id >= OPT_COUNT)
		return NULL;

	if (opts[id].type != OPT_TYPE_STR)
		return NULL;

	return opts[id].data.as_str;
}

struct rl_context
{
	unsigned int is_encrypt : 1;
	lzma_vli lzma_filter;
	lzma_check lzma_check;
	uint32_t lzma_preset;
	uint32_t lzma_threads;
	uint64_t lzma_mem_limit;
	lzma_options_lzma lzma_options;
	lzma_stream lzma_stream;
	const EVP_CIPHER *cipher;
	const EVP_MD *hash;
	int hash_rounds;
	unsigned char salt[8];
	unsigned char key[256 / 8];
	unsigned char iv[128 / 8];
	EVP_CIPHER_CTX *cipher_ctx;
};

static struct tm get_local_time(void)
{
	time_t tme;

	tme = time(NULL);
	return *localtime(&tme);
}

static char *build_out_filename(struct rl_context *ctx, size_t buf_size, char *buf, const char *in_filename)
{
	char *tmp;
	struct tm tm;
	char date_buf[64];

	strncpy(buf, in_filename, buf_size);
	buf[buf_size - 1] = '\0';

	if (ctx->is_encrypt)
	{
		tmp = strrchr(buf, '.');
		if (tmp && strcmp(tmp, ".log") == 0)
			*tmp = '\0';

		tm = get_local_time();
		strftime(date_buf, sizeof(date_buf), "-%Y-%m-%d-%H-%M-%S.log.xz.aes", &tm);

		strncat(buf, date_buf, buf_size);
	}
	else
	{
		const char ext_s[] = ".xz.aes";
		char *ext;

		ext = strstr(buf, ext_s);
		if (ext && ext[sizeof(ext_s) - 1] == '\0')
			ext[0] = '\0';
	}

	return buf;
}

static int open_files(int log_dir_fd, const char *in_filename, int out_dir_fd, const char *out_filename, FILE **infp, FILE **outfp)
{
	struct stat st;
	int infd = -1, outfd = -1;

	*infp = NULL;
	*outfp = NULL;

	fstatat(log_dir_fd, in_filename, &st, 0);
	if (!S_ISREG(st.st_mode))
		goto fail_not_reg_file;

	infd = openat(log_dir_fd, in_filename, O_RDONLY);
	if (infd < 0)
		goto fail_open_infd;

	*infp = fdopen(infd, "rb");
	infd = -1;
	if (!*infp)
		goto fail_open_infp;

	outfd = openat(out_dir_fd, out_filename, O_CREAT | O_WRONLY, st.st_mode);
	if (outfd < 0)
		goto fail_open_outfd;

	*outfp = fdopen(outfd, "wb");
	outfd = -1;
	if (!*outfp)
		goto fail_open_outfp;

	return 0;

fail_open_outfp:
	if (outfd >= 0)
		close(outfd);

fail_open_outfd:
	fclose(*infp);

fail_open_infp:
	if (infd >= 0)
		close(infd);

fail_open_infd:
fail_not_reg_file:
	return -1;
}

enum crypto_pipeline_id
{
	CRYPTO_PIPELINE_ENCRYPT = 0,
	CRYPTO_PIPELINE_DECRYPT,
	CRYPTO_PIPELINE_COUNT
};

enum crypto_step_id
{
	CRYPTO_STEP_READ = 0,
	CRYPTO_STEP_CRYPTO,
	CRYPTO_STEP_LZMA,
	CRYPTO_STEP_WRITE,
	CRYPTO_STEP_COUNT
};

struct crypto_step
{
	enum crypto_step_id step;
	size_t inbuf_size;
	unsigned char *inbuf;
	unsigned int eof : 1;
	/* Must be set when the step has not finished processing the current inbuf. */
	unsigned int busy : 1;
};

int do_crypto(struct rl_context *ctx, FILE *infp, FILE *outfp)
{
	int status = -1;
	lzma_ret lzret;
	int result;
	unsigned char inbuf[BLOCK_SIZE];
	unsigned char lzmabuf[BLOCK_SIZE];
	unsigned char cryptobuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];

#define CRYPTO_STEP(s, inb) { .step = (s), .inbuf_size = 0, .inbuf = (inb), .eof = 0, .busy = 0 }
#define CRYPTO_STEP_END() CRYPTO_STEP(CRYPTO_STEP_COUNT, NULL)
	struct crypto_step encrypt_steps[] = {
		CRYPTO_STEP(CRYPTO_STEP_READ,   NULL),
		CRYPTO_STEP(CRYPTO_STEP_LZMA,   inbuf),
		CRYPTO_STEP(CRYPTO_STEP_CRYPTO, lzmabuf),
		CRYPTO_STEP(CRYPTO_STEP_WRITE,  cryptobuf),
		CRYPTO_STEP_END()
	};
	struct crypto_step decrypt_steps[] = {
		CRYPTO_STEP(CRYPTO_STEP_READ,   NULL),
		CRYPTO_STEP(CRYPTO_STEP_CRYPTO, inbuf),
		CRYPTO_STEP(CRYPTO_STEP_LZMA,   cryptobuf),
		CRYPTO_STEP(CRYPTO_STEP_WRITE,  lzmabuf),
		CRYPTO_STEP_END()
	};
#undef CRYPTO_STEP

	struct crypto_step *crypto_steps[CRYPTO_PIPELINE_COUNT] = {
		[CRYPTO_PIPELINE_ENCRYPT] = encrypt_steps,
		[CRYPTO_PIPELINE_DECRYPT] = decrypt_steps
	};

	enum crypto_pipeline_id pipeline = ctx->is_encrypt ? CRYPTO_PIPELINE_ENCRYPT : CRYPTO_PIPELINE_DECRYPT;
	size_t crypto_step_count = 0;

	if (ctx->is_encrypt)
	{
		const lzma_mt options = {
			.flags = 0,
			.threads = ctx->lzma_threads,
			.block_size = 0,
			.timeout = 0,
			.preset = ctx->lzma_preset,
			.filters = (const lzma_filter[]) {
				{ .id = ctx->lzma_filter, .options = &ctx->lzma_options },
				{ .id = LZMA_VLI_UNKNOWN, .options = NULL }
			},
			.check = ctx->lzma_check
		};

		lzret = lzma_stream_encoder_mt(&ctx->lzma_stream, &options);
	}
	else
		lzret = lzma_stream_decoder(&ctx->lzma_stream, ctx->lzma_mem_limit, LZMA_TELL_NO_CHECK | LZMA_TELL_UNSUPPORTED_CHECK);

	if (lzret != LZMA_OK)
		goto fail_lzma_init;

	result = EVP_CipherInit(ctx->cipher_ctx, ctx->cipher, NULL, NULL, ctx->is_encrypt);
	if (!result)
		goto fail_cipher_init;

	result = EVP_CipherInit(ctx->cipher_ctx, NULL, ctx->key, ctx->iv, -1);
	if (!result)
		goto fail_cipher_init;

	for (struct crypto_step *step = &crypto_steps[pipeline][0]; step->step != CRYPTO_STEP_COUNT; step++)
		crypto_step_count++;

	while (!crypto_steps[pipeline][crypto_step_count - 1].eof)
	{
		size_t first_step = 0;

		/* Restart from the last busy step */
		for (size_t i = 0; i < crypto_step_count; i++)
		{
			size_t step_idx = crypto_step_count - 1 - i;
			struct crypto_step *step = &crypto_steps[pipeline][step_idx];

			if (!step->eof && step->busy)
			{
				first_step = step_idx;
				break;
			}
		}

		for (size_t i = first_step; i < crypto_step_count; i++)
		{
			struct crypto_step *step = &crypto_steps[pipeline][i];
			struct crypto_step *prev_step = i > 0 ? &crypto_steps[pipeline][i - 1] : NULL;
			struct crypto_step *next_step = i < crypto_step_count - 1 ? &crypto_steps[pipeline][i + 1] : NULL;

			if (step->eof)
				continue;

			switch (step->step)
			{
				case CRYPTO_STEP_READ:
				{
					size_t rsize;

					rsize = fread(inbuf, 1, sizeof(inbuf), infp);
					if (ferror(infp))
						goto fail_process;

					step->eof = feof(infp);
					next_step->inbuf_size = rsize;
					break;
				}

				case CRYPTO_STEP_LZMA:
				{
					size_t osize = 0;

					if (!step->busy)
					{
						ctx->lzma_stream.next_in = step->inbuf;
						ctx->lzma_stream.avail_in = step->inbuf_size;
					}

					ctx->lzma_stream.next_out = lzmabuf;
					ctx->lzma_stream.avail_out = sizeof(lzmabuf);

					step->busy = 0;

					if (ctx->lzma_stream.avail_in)
					{
						lzret = lzma_code(&ctx->lzma_stream, LZMA_RUN);
						if (ctx->lzma_stream.avail_in > 0)
							step->busy = 1;
					}
					else if (prev_step->eof)
					{
						lzret = lzma_code(&ctx->lzma_stream, LZMA_FINISH);
						if (lzret == LZMA_OK)
							step->busy = 1;
					}

					if (lzret == LZMA_STREAM_END)
					{
						step->eof = 1;
						lzret = LZMA_OK;
					}

					if (lzret != LZMA_OK)
						goto fail_process;

					osize = sizeof(lzmabuf) - ctx->lzma_stream.avail_out;

					step->inbuf_size = 0;
					next_step->inbuf_size = osize;
					break;
				}
						
				case CRYPTO_STEP_CRYPTO:
				{
					int osize = 0;

					result = 1;

					if (step->inbuf_size)
						result = EVP_CipherUpdate(ctx->cipher_ctx, cryptobuf, &osize, step->inbuf, step->inbuf_size);

					if (prev_step->eof)
					{
						step->busy = 1;

						if (!step->inbuf_size)
						{
							result = EVP_CipherFinal(ctx->cipher_ctx, cryptobuf, &osize);
							step->busy = 0;
							step->eof = 1;
						}
					}

					if (!result)
						goto fail_process;

					step->inbuf_size = 0;
					next_step->inbuf_size = osize;
					break;
				}

				case CRYPTO_STEP_WRITE:
				{
					if (step->inbuf_size)
					{
						fwrite(step->inbuf, 1, step->inbuf_size, outfp);
						if (ferror(outfp))
							goto fail_process;
					}

					step->inbuf_size = 0;
					step->eof = prev_step->eof;
					break;
				}

				default:
					break;
			}
		}
	}

	status = 0;

fail_process:
	EVP_CIPHER_CTX_reset(ctx->cipher_ctx);

fail_cipher_init:
	lzma_end(&ctx->lzma_stream);

fail_lzma_init:
	return status;
}

int main(int argc, char **argv)
{
#define OPT_STR(e, n) [e] = { .type = OPT_TYPE_STR, .name = n }
#define OPT_INT(e, n) [e] = { .type = OPT_TYPE_INT, .name = n }
	struct opt opts[] = {
		OPT_STR(OPT_DECRYPT, "-decrypt"),
		OPT_STR(OPT_ENCRYPT, "-encrypt"),
		OPT_STR(OPT_LOG, "-log"),
		OPT_STR(OPT_PATH, "-path"),
		OPT_INT(OPT_THREADS, "-threads")
	};
#undef OPT
	int status = 1;
	int result;
	struct rl_context ctx;
	const char *password;
	int log_dir_fd;
	DIR *log_dir;
	int out_dir_fd;
	struct dirent *log_dir_entry;

	result = parse_opts(argc, argv, OPT_COUNT, opts);
	if (result < 0
			|| get_opt_defined(opts, OPT_DECRYPT) == !!get_opt_defined(opts, OPT_ENCRYPT)
			|| !get_opt_defined(opts, OPT_LOG)
			|| !get_opt_defined(opts, OPT_PATH)
			|| (get_opt_defined(opts, OPT_THREADS) && get_opt_int(opts, OPT_THREADS) <= 0))
	{
		fprintf(stderr, "Usage: %s -decrypt|-encrypt <password> -log <log_dir> -path <dest_dir> [-threads <count>]\n", (argc >= 1) ? argv[0] : "rotate_logs");
		return 1;
	}

	ctx.is_encrypt = !!get_opt_str(opts, OPT_ENCRYPT);
	ctx.lzma_filter = LZMA_FILTER_LZMA2;
	ctx.lzma_check = LZMA_CHECK_CRC64;
	ctx.lzma_preset = 5 | LZMA_PRESET_EXTREME;
	ctx.lzma_threads = get_opt_defined(opts, OPT_THREADS) ? get_opt_int(opts, OPT_THREADS) : 1;
	ctx.lzma_mem_limit = UINT64_MAX;
	ctx.lzma_stream = (lzma_stream)LZMA_STREAM_INIT;

	if (ctx.is_encrypt && !lzma_filter_encoder_is_supported(ctx.lzma_filter))
		goto fail_lzma_settings;

	if (!ctx.is_encrypt && !lzma_filter_decoder_is_supported(ctx.lzma_filter))
		goto fail_lzma_settings;

	if (!lzma_check_is_supported(ctx.lzma_check))
		goto fail_lzma_settings;

	if (lzma_lzma_preset(&ctx.lzma_options, ctx.lzma_preset))
		goto fail_lzma_settings;

	ctx.cipher = EVP_aes_256_cbc();
	ctx.hash = EVP_sha256();
	ctx.hash_rounds = 5;

	for (size_t i = 0; i < sizeof(ctx.salt); i++)
		ctx.salt[i] = (i < sizeof(PASSWORD_SALT)) ? (PASSWORD_SALT)[i] : '\0';

	OPENSSL_assert(EVP_CIPHER_key_length(ctx.cipher) == sizeof(ctx.key));
	OPENSSL_assert(EVP_CIPHER_iv_length(ctx.cipher) == sizeof(ctx.iv));

	password = ctx.is_encrypt ? get_opt_str(opts, OPT_ENCRYPT) : get_opt_str(opts, OPT_DECRYPT);

	result = EVP_BytesToKey(ctx.cipher, ctx.hash,
			ctx.salt,
			(unsigned char *)password, strlen(password),
			ctx.hash_rounds, ctx.key, ctx.iv);

	OPENSSL_assert(result == sizeof(ctx.key));

	ctx.cipher_ctx = EVP_CIPHER_CTX_new();
	if (!ctx.cipher_ctx)
		goto fail_cipher_ctx_new;

	log_dir_fd = open(get_opt_str(opts, OPT_LOG), O_RDONLY | O_DIRECTORY);
	if (log_dir_fd < 0)
		goto fail_open_log_dir;

	log_dir = fdopendir(log_dir_fd);
	if (!log_dir)
	{
		close(log_dir_fd);
		goto fail_open_log_dir;
	}

	out_dir_fd = open(get_opt_str(opts, OPT_PATH), O_RDONLY | O_DIRECTORY);
	if (out_dir_fd < 0)
		goto fail_open_out_dir;

	while ((log_dir_entry = readdir(log_dir)))
	{
		char out_filename[1024];
		FILE *infp = NULL, *outfp = NULL;

		build_out_filename(&ctx, sizeof(out_filename), out_filename, log_dir_entry->d_name);

		result = open_files(log_dir_fd, log_dir_entry->d_name, out_dir_fd, out_filename, &infp, &outfp);
		if (result < 0)
			continue;

		result = do_crypto(&ctx, infp, outfp);

		fclose(outfp);
		fclose(infp);

		if (result == 0)
			unlinkat(log_dir_fd, log_dir_entry->d_name, 0);
		else
			unlinkat(out_dir_fd, out_filename, 0);

		if (result < 0)
			goto fail_crypto;
	}

	status = 0;	

fail_crypto:
	close(out_dir_fd);

fail_open_out_dir:
	closedir(log_dir);

fail_open_log_dir:
	EVP_CIPHER_CTX_free(ctx.cipher_ctx);

fail_cipher_ctx_new:
fail_lzma_settings:
	printf("%s\n", (status == 0) ? "OK" : "Critical");

	return status;
}
