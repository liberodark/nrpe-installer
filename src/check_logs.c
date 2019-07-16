#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
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

#define DEFAULT_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static inline int mini(int a, int b) {
	return a < b ? a : b;
}

enum opt_id
{
	OPT_AUTOCLEAN = 0,
	OPT_CHECK,
	OPT_CLEAN,
	OPT_COMPRESS,
	OPT_CRON,
	OPT_DECRYPT,
	OPT_ENCRYPT,
	OPT_EXTRACT,
	OPT_IN,
	OPT_IN_PATH,
	OPT_KEEP,
	OPT_LOCK,
	OPT_OUT,
	OPT_OUT_PATH,
	OPT_THREADS,
	OPT_COUNT
};

enum opt_type
{
	OPT_TYPE_INVAL = 0,
	OPT_TYPE_NONE,
	OPT_TYPE_INT,
	OPT_TYPE_STR,
	OPT_TYPE_DURATION,
	OPT_TYPE_CRON
};

struct opt
{
	enum opt_type type;
	const char *name;
	union {
		int as_int;
		const char *as_str;
		time_t as_duration;
		struct
		{
			int M;
			int H;
			int d;
			int m;
			int w;
		} as_cron;
	} data;
};

static inline const char *my_basename(const char *s) {
	const char *p;

	p = strrchr(s, '/');
	if (!p)
		return s;

	if (p[1] == '\0')
	{
		if (p == s)
			return p;

		while (&p[-1] >= s && p[-1] != '/')
			p--;

		return p;
	}

	return &p[1];
}

static inline const char *skip_spaces(const char *p) {
	while (isspace(*p))
		p++;

	return p;
}

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

			matched = 1;

			opt->data.as_str = "";
			if (opt->type != OPT_TYPE_NONE)
			{
				if (i >= argc - 1)
					return -1;

				opt->data.as_str = argv[++i];
			}
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
			case OPT_TYPE_NONE:
				break;

			case OPT_TYPE_INT:
			{
				const char *p = opt->data.as_str;
				char *endp;
				int n;

				if (!*p)
					return -1;

				n = strtol(p, &endp, 0);
				if (*endp)
					return -1;

				opt->data.as_int = n;
				break;
			}

			case OPT_TYPE_STR:
				break;

			case OPT_TYPE_DURATION:
			{
				const char *p = opt->data.as_str;
				char *endp;
				struct tm tm;
				time_t duration;
				long int n;

				if (!*p)
					return -1;

				duration = 0;
				tm = *localtime(&duration);

				while (*p)
				{
					n = strtol(p, &endp, 10);
					if (endp == p || n < 0)
						return -1;
					p = endp;

					switch (*p)
					{
						case 'h': tm.tm_hour += n; break;
						case 'd': tm.tm_mday += n; break;
						case 'm': tm.tm_mon += n; break;
						case 'y': tm.tm_year += n; break;
						default:
							return -1;
					}
					p++;
				}

				duration = mktime(&tm);
				if (duration < 0)
					return -1;

				opt->data.as_duration = duration;
				break;
			}

			case OPT_TYPE_CRON:
			{
				const char *hardcoded[] = {
					"@hourly",   "0 * * * *",
					"@daily",    "0 0 * * *",
					"@midnight", "0 0 * * *",
					"@weekly",   "0 0 * * 0",
					"@monthly",  "0 0 1 * *",
					"@annually", "0 0 1 1 *"
					"@yearly",   "0 0 1 1 *"
				};
				const char *p;
				char *endp;
				int params[5];
				long int n;

				for (size_t j = 0; j < ARRAY_SIZE(hardcoded); j += 2)
				{
					if (strcmp(opt->data.as_str, hardcoded[j]) == 0)
					{
						opt->data.as_str = hardcoded[j + 1];
						break;
					}
				}

				p = opt->data.as_str;

				for (size_t j = 0; j < 5; j++)
				{
					if (p != opt->data.as_str
							&& !isspace(*p))
						return -1;

					p = skip_spaces(p);
					if (!*p)
						return -1;

					if (*p == '*')
					{
						params[j] = INT_MAX;
						p++;
						continue;
					}

					n = strtol(p, &endp, 10);
					if (endp == p || n < 0)
						return -1;
					p = endp;

					params[j] = n;
				}

				p = skip_spaces(p);
				if (*p)
					return -1;

				if ((params[0] != INT_MAX && params[0] > 59)
						|| (params[1] != INT_MAX && params[1] > 23)
						|| (params[2] != INT_MAX && (params[2] < 1 || params[2] > 31))
						|| (params[3] != INT_MAX && (params[3] < 1 || params[3] > 12))
						|| (params[4] != INT_MAX && params[4] > 6))
					return -1;

				opt->data.as_cron.M = params[0];
				opt->data.as_cron.H = params[1];
				opt->data.as_cron.d = params[2];
				opt->data.as_cron.m = params[3];
				opt->data.as_cron.w = params[4];
				break;
			}
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

enum crypto_pipeline_id
{
	CRYPTO_PIPELINE_COMPRESS = 0,
	CRYPTO_PIPELINE_EXTRACT,
	CRYPTO_PIPELINE_COMPRESS_ENCRYPT_DIGEST,
	CRYPTO_PIPELINE_DIGEST_DECRYPT_EXTRACT,
	CRYPTO_PIPELINE_DIGEST,
	CRYPTO_PIPELINE_COUNT
};

struct rl_context
{
	int lock_fd;
	unsigned int pipeline_has_encrypt : 1;
	unsigned int pipeline_has_decrypt : 1;
	unsigned int pipeline_has_compress : 1;
	unsigned int pipeline_has_extract : 1;
	unsigned int pipeline_has_in_digest : 1;
	unsigned int pipeline_has_out_digest : 1;
	enum crypto_pipeline_id pipeline;
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
	const EVP_MD *digest_type;
	EVP_MD_CTX *digest_ctx;
};

static struct tm get_local_time(void)
{
	time_t tme;

	tme = time(NULL);
	return *localtime(&tme);
}

static char *build_out_filename(struct rl_context *ctx, size_t buf_size, char *buf, const char *in_filename, int is_digest)
{
	struct tm tm;
	char date_buf[64];

	strncpy(buf, in_filename, buf_size);
	buf[buf_size - 1] = '\0';

	if (is_digest)
		return strncat(buf, ".sha", buf_size);

	if (ctx->pipeline == CRYPTO_PIPELINE_COMPRESS
			|| ctx->pipeline == CRYPTO_PIPELINE_COMPRESS_ENCRYPT_DIGEST)
	{
		const char *old_ext = NULL;
		const char *ext = ctx->pipeline == CRYPTO_PIPELINE_COMPRESS ? ".xz" : ".xz.aes";

		old_ext = strrchr(in_filename, '.');
		if (old_ext)
			buf[(uintptr_t)old_ext - (uintptr_t)in_filename] = '\0';

		tm = get_local_time();
		strftime(date_buf, sizeof(date_buf), "-%Y-%m-%d-%H-%M-%S", &tm);

		strncat(buf, date_buf, buf_size);
		if (old_ext)
			strncat(buf, old_ext, buf_size);
		strncat(buf, ext, buf_size);
	}
	else
	{
		const char *ext = ctx->pipeline == CRYPTO_PIPELINE_EXTRACT ? ".xz" : ".xz.aes";
		int result;
		size_t ext_len;
		size_t fname_len;

		ext_len = strlen(ext);
		fname_len = strlen(buf);

		if (fname_len >= ext_len)
		{
			size_t buf_off = fname_len - ext_len;

			result = strcmp(&buf[buf_off], ext);
			if (result == 0)
				buf[buf_off] = '\0';
		}
	}

	return buf;
}

static int open_files(int in_dir_fd, const char *in_filename, int out_dir_fd, const char *out_filename, FILE **infp, FILE **outfp)
{
	struct stat st;
	int infd = -1, outfd = -1;

	if (in_filename)
	{
		*infp = NULL;

		fstatat(in_dir_fd, in_filename, &st, 0);
		if (!S_ISREG(st.st_mode))
			goto fail;

		infd = openat(in_dir_fd, in_filename, O_RDONLY);
		if (infd < 0)
			goto fail;

		*infp = fdopen(infd, "rb");
		infd = -1;
		if (!*infp)
			goto fail;
	}

	if (out_filename)
	{
		*outfp = NULL;

		outfd = openat(out_dir_fd, out_filename, O_CREAT | O_WRONLY, DEFAULT_FILE_MODE);
		if (outfd < 0)
			goto fail;

		*outfp = fdopen(outfd, "wb");
		outfd = -1;
		if (!*outfp)
			goto fail;
	}

	return 0;

fail:
	if (outfd >= 0)
		close(outfd);

	if (infp && *infp)
		fclose(*infp);

	if (infd >= 0)
		close(infd);

	return -1;
}

enum crypto_step_id
{
	CRYPTO_STEP_READ = 0,
	CRYPTO_STEP_CRYPTO,
	CRYPTO_STEP_LZMA,
	CRYPTO_STEP_DIGEST,
	CRYPTO_STEP_WRITE,
	CRYPTO_STEP_COUNT
};

struct crypto_step
{
	enum crypto_step_id step;
	FILE *fp;
	size_t inbuf_size;
	/* Can be used to track the last busy read */
	size_t inbuf_idx;
	unsigned char *inbuf;
	size_t outbuf_size;
	unsigned char *outbuf;
	unsigned int eof : 1;
	/* Must be set when the step has not finished processing the current inbuf. */
	unsigned int busy : 1;
};

int do_crypto(struct rl_context *ctx, FILE *infp, FILE *outfp, FILE *digestinoutfp)
{
	int status = -1;
	lzma_ret lzret;
	int result;
	unsigned char readbuf[BLOCK_SIZE];
	unsigned char lzmabuf[BLOCK_SIZE];
	unsigned char cryptobuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
	unsigned char writebuf[BLOCK_SIZE];
	unsigned char digestbuf[EVP_MAX_MD_SIZE] = {0};
	unsigned char digestchkbuf[EVP_MAX_MD_SIZE] = {0};

#define CRYPTO_STEPD(s, inb, outb, f) { .step = (s), .fp = (f), .inbuf_size = 0, .inbuf_idx = 0, .inbuf = (inb), .outbuf_size = sizeof(outb), .outbuf = (outb), .eof = 0, .busy = 0 }
#define CRYPTO_STEP(s, inb, outb) CRYPTO_STEPD(s, inb, outb, NULL)
#define CRYPTO_STEPI(s, f, outb) CRYPTO_STEPD(s, NULL, outb, f)
#define CRYPTO_STEPO(s, inb, f) CRYPTO_STEPD(s, inb, NULL, f)
#define CRYPTO_STEP_END() CRYPTO_STEP(CRYPTO_STEP_COUNT, NULL, NULL)
	struct crypto_step compress_steps[] = {
		CRYPTO_STEPI(CRYPTO_STEP_READ,  infp,    readbuf),
		CRYPTO_STEP (CRYPTO_STEP_LZMA,  readbuf, lzmabuf),
		CRYPTO_STEPO(CRYPTO_STEP_WRITE, lzmabuf, outfp),
		CRYPTO_STEP_END()
	};
	struct crypto_step extract_steps[] = {
		CRYPTO_STEPI(CRYPTO_STEP_READ,  infp,    readbuf),
		CRYPTO_STEP (CRYPTO_STEP_LZMA,  readbuf, lzmabuf),
		CRYPTO_STEPO(CRYPTO_STEP_WRITE, lzmabuf, outfp),
		CRYPTO_STEP_END()
	};
	struct crypto_step compress_encrypt_digest_steps[] = {
		CRYPTO_STEPI(CRYPTO_STEP_READ,   infp,      readbuf),
		CRYPTO_STEP (CRYPTO_STEP_LZMA,   readbuf,   lzmabuf),
		CRYPTO_STEP (CRYPTO_STEP_CRYPTO, lzmabuf,   cryptobuf),
		CRYPTO_STEPD(CRYPTO_STEP_WRITE,  cryptobuf, writebuf, outfp),
		CRYPTO_STEP (CRYPTO_STEP_DIGEST, writebuf,  digestbuf),
		CRYPTO_STEPO(CRYPTO_STEP_WRITE,  digestbuf, digestinoutfp),
		CRYPTO_STEP_END()
	};
	struct crypto_step digest_decrypt_extract_steps[] = {
		CRYPTO_STEPI(CRYPTO_STEP_READ,   infp,      readbuf),
		CRYPTO_STEP( CRYPTO_STEP_CRYPTO, readbuf,   cryptobuf),
		CRYPTO_STEP( CRYPTO_STEP_LZMA,   cryptobuf, lzmabuf),
		CRYPTO_STEPO(CRYPTO_STEP_WRITE,  lzmabuf,   outfp),
		CRYPTO_STEP_END()
	};
	struct crypto_step digest_steps[] = {
		CRYPTO_STEPI(CRYPTO_STEP_READ,   digestinoutfp, digestchkbuf),
		CRYPTO_STEPI(CRYPTO_STEP_READ,   infp,          readbuf),
		CRYPTO_STEP (CRYPTO_STEP_DIGEST, readbuf,       digestbuf),
		CRYPTO_STEP_END()
	};
#undef CRYPTO_STEP
	struct crypto_step *crypto_pipelines[CRYPTO_PIPELINE_COUNT] = {
		[CRYPTO_PIPELINE_COMPRESS] = compress_steps,
		[CRYPTO_PIPELINE_EXTRACT] = extract_steps,
		[CRYPTO_PIPELINE_COMPRESS_ENCRYPT_DIGEST] = compress_encrypt_digest_steps,
		[CRYPTO_PIPELINE_DIGEST_DECRYPT_EXTRACT] = digest_decrypt_extract_steps,
		[CRYPTO_PIPELINE_DIGEST] = digest_steps
	};
	size_t crypto_step_count = 0;
	struct crypto_step *pipeline_steps = crypto_pipelines[ctx->pipeline];

	lzret = LZMA_OK;

	if (ctx->pipeline_has_compress)
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
	else if (ctx->pipeline_has_extract)
		lzret = lzma_stream_decoder(&ctx->lzma_stream, ctx->lzma_mem_limit, LZMA_TELL_NO_CHECK | LZMA_TELL_UNSUPPORTED_CHECK);

	if (lzret != LZMA_OK)
		goto fail_lzma_init;

	if (ctx->pipeline_has_encrypt || ctx->pipeline_has_decrypt)
	{
		result = EVP_CipherInit(ctx->cipher_ctx, ctx->cipher, NULL, NULL, ctx->pipeline_has_encrypt);
		if (!result)
			goto fail_cipher_init;

		result = EVP_CipherInit(ctx->cipher_ctx, NULL, ctx->key, ctx->iv, -1);
		if (!result)
			goto fail_cipher_init;
	}

	if (ctx->pipeline_has_in_digest || ctx->pipeline_has_out_digest)
	{
		result = EVP_DigestInit(ctx->digest_ctx, ctx->digest_type);
		if (!result)
			goto fail_digest_init;
	}

	for (struct crypto_step *step = &pipeline_steps[0]; step->step != CRYPTO_STEP_COUNT; step++)
		crypto_step_count++;

	while (!pipeline_steps[crypto_step_count - 1].eof)
	{
		size_t first_step = 0;

		/* Restart from the last busy step */
		for (size_t i = 0; i < crypto_step_count; i++)
		{
			size_t step_idx = crypto_step_count - 1 - i;
			struct crypto_step *step = &pipeline_steps[step_idx];

			if (!step->eof && step->busy)
			{
				first_step = step_idx;
				break;
			}
		}

		for (size_t i = first_step; i < crypto_step_count; i++)
		{
			struct crypto_step *step = &pipeline_steps[i];
			struct crypto_step *prev_step = i > 0 ? &pipeline_steps[i - 1] : NULL;
			struct crypto_step *next_step = i < crypto_step_count - 1 ? &pipeline_steps[i + 1] : NULL;

			if (step->eof)
				continue;

			switch (step->step)
			{
				case CRYPTO_STEP_READ:
				{
					size_t rsize;

					rsize = fread(step->outbuf, 1, step->outbuf_size, step->fp);
					if (ferror(step->fp))
						goto fail_process;

					step->eof = feof(step->fp);
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

					ctx->lzma_stream.next_out = step->outbuf;
					ctx->lzma_stream.avail_out = step->outbuf_size;

					step->busy = 0;

					lzret = LZMA_OK;

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

					osize = step->outbuf_size - ctx->lzma_stream.avail_out;

					step->inbuf_size = 0;
					next_step->inbuf_size = osize;
					break;
				}

				case CRYPTO_STEP_CRYPTO:
				{
					int osize = 0;

					result = 1;

					if (step->inbuf_size)
						result = EVP_CipherUpdate(ctx->cipher_ctx, step->outbuf, &osize, step->inbuf, step->inbuf_size);

					if (prev_step->eof)
					{
						step->busy = 1;

						if (!step->inbuf_size)
						{
							result = EVP_CipherFinal(ctx->cipher_ctx, step->outbuf, &osize);
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

				case CRYPTO_STEP_DIGEST:
				{
					unsigned int osize = 0;

					result = 1;

					if (step->inbuf_size)
						result = EVP_DigestUpdate(ctx->digest_ctx, step->inbuf, step->inbuf_size);

					if (result && prev_step->eof)
					{
						result = EVP_DigestFinal(ctx->digest_ctx, step->outbuf, &osize);
						step->eof = 1;
					}

					if (!result)
						goto fail_process;

					step->inbuf_size = 0;
					if (next_step)
						next_step->inbuf_size = osize;
					break;
				}

				case CRYPTO_STEP_WRITE:
				{
					size_t osize = step->inbuf_size;

					if (!step->busy && step->inbuf_size)
					{
						fwrite(step->inbuf, 1, step->inbuf_size, step->fp);
						if (ferror(outfp))
							goto fail_process;
					}

					if (next_step)
					{
						osize = mini(step->inbuf_size, step->outbuf_size);
						memcpy(step->outbuf, &step->inbuf[step->inbuf_idx], osize);
					}

					step->inbuf_idx = osize;
					step->inbuf_size -= step->inbuf_idx;

					step->busy = 1;

					if (!step->inbuf_size)
					{
						step->busy = 0;
						step->inbuf_idx = 0;
					}

					if (!step->busy)
						step->eof = prev_step->eof;
					if (next_step)
						next_step->inbuf_size = osize;
					break;
				}

				default:
					break;
			}
		}
	}

	if (ctx->pipeline == CRYPTO_PIPELINE_DIGEST)
	{
		result = memcmp(digestchkbuf, digestbuf, sizeof(digestbuf));
		if (result != 0)
			goto fail_process;
	}

	status = 0;

fail_process:
	if (ctx->pipeline_has_in_digest || ctx->pipeline_has_out_digest)
		EVP_MD_CTX_reset(ctx->digest_ctx);

fail_digest_init:
	if (ctx->pipeline_has_encrypt || ctx->pipeline_has_decrypt)
		EVP_CIPHER_CTX_reset(ctx->cipher_ctx);

fail_cipher_init:
	if (ctx->pipeline_has_compress || ctx->pipeline_has_extract)
		lzma_end(&ctx->lzma_stream);

fail_lzma_init:
	return status;
}

int print_usage(int argc, char **argv)
{
	fprintf(stderr,
			"Usage: %s <action> [<subaction> ...] <path_spec> [-keep] [-lock <lock_file> [-cron <cron_spec>]] [-threads <count>]\n"
			"\n"
			"Options:\n"
			"    -keep                    Do not remove input files\n"
			"    -lock <lock_file>        Avoid concurrent execution by locking <lock_file>\n"
			"                             upon startup\n"
			"    -cron <cron_spec>        Abort execution if runned before the end of\n"
			"                             the current period\n"
			"                             Refer to the <cron_spec> section\n"
			"    -threads <count>         Set the thread count available for compression\n"
			"\n"
			"<action>: Must be exactly one of the following:\n"
			"    -encrypt <password>      Compress, encrypt and produce a hash\n"
			"    -decrypt <password>      Check the hash, decrypt and extract\n"
			"    -compress                Compress\n"
			"    -extract                 Extract\n"
			"    -check                   Check the hash\n"
			"    -clean <duration>        Remove files older than <duration>\n"
			"                             Refer to the <duration> section\n"
			"\n"
			"<subaction>: Can be zero or more of the following:\n"
			"    -autoclean <duration>    Remove files older than <duration> inside the\n"
			"                             <action> explicit or implicit -out or -out-path\n"
			"\n"
			"<path_spec>: Can be a combination of the following:\n"
			"    -in-path <dir>           The input directory\n"
			"    -in <file>               The input file\n"
			"    -out-path <dir>          The output directory\n"
			"    -out <file>              The output file\n"
			"If -in-path is specified then -out cannot be specified\n"
			"Refer to the \"Available <action> and <path_spec> combinations\" section\n"
			"\n"
			"<duration>: The result of concatenation of one or more of the following:\n"
			"    <n>h                     Hour count\n"
			"    <n>d                     Day count\n"
			"    <n>m                     Month count\n"
			"    <n>y                     Year count\n"
			"The resulting <duration> is the sum of all individual durations\n"
			"(e.g. 3m1d1h2h is 3 months + 1 day + 3 hours)\n"
			"\n"
			"<cron_spec>: Simplified cron expression, must be one of the following:\n"
			"    <M> <H> <d> <m> <w>      Any of them can be either a number or *, with:\n"
			"                                 <M>: Minute [0-59]\n"
			"                                 <H>: Hour [0-23]\n"
			"                                 <d>: Day of the month [1-31]\n"
			"                                 <m>: Month [1-12]\n"
			"                                 <w>: Day of the week [0-6] (0 is Sunday)\n"
			"    @hourly                  Same as 0 * * * *\n"
			"    @daily                   Same as 0 0 * * *\n"
			"    @midnight                Same as @daily\n"
			"    @weekly                  Same as 0 0 * * 0\n"
			"    @monthly                 Same as 0 0 1 * *\n"
			"    @annually                Same as 0 0 1 1 *\n"
			"    @yearly                  Same as @annually\n"
			"\n"
			"Available <action> and <path_spec> combinations:\n"
			"    -encrypt <password> -in-path <dir> [-out-path <dir>]\n"
			"    -encrypt <password> -in <file> [-out-path <dir> | -out <file>]\n"
			"\n"
			"    -decrypt <password> -in-path <dir> [-out-path <dir>]\n"
			"    -decrypt <password> -in <file> [-out-path <dir> | -out <file>]\n"
			"\n"
			"    -compress -in-path <dir> [-out-path <dir>]\n"
			"    -compress -in <file> [-out-path <dir> | -out <file>]\n"
			"\n"
			"    -extract -in-path <dir> [-out-path <dir>]\n"
			"    -extract -in <file> [-out-path <dir> | -out <file>]\n"
			"\n"
			"    -check -in-path <dir>\n"
			"    -check -in <file>\n"
			"\n"
			"    -clean <duration> -in-path <dir>\n"
			"    -clean <duration> -in <file>\n", (argc >= 1) ? argv[0] : "rotate_logs");
	return 1;
}

int main(int argc, char **argv)
{
#define OPT_NONE(e, n) [e] = { .type = OPT_TYPE_NONE, .name = n }
#define OPT_STR(e, n) [e] = { .type = OPT_TYPE_STR, .name = n }
#define OPT_INT(e, n) [e] = { .type = OPT_TYPE_INT, .name = n }
#define OPT_DURATION(e, n) [e] = { .type = OPT_TYPE_DURATION, .name = n }
#define OPT_CRON(e, n) [e] = { .type = OPT_TYPE_CRON, .name = n }
	struct opt opts[] = {
		OPT_DURATION(OPT_AUTOCLEAN, "-autoclean"),
		OPT_NONE(OPT_CHECK, "-check"),
		OPT_DURATION(OPT_CLEAN, "-clean"),
		OPT_NONE(OPT_COMPRESS, "-compress"),
		OPT_CRON(OPT_CRON, "-cron"),
		OPT_STR(OPT_DECRYPT, "-decrypt"),
		OPT_STR(OPT_ENCRYPT, "-encrypt"),
		OPT_NONE(OPT_EXTRACT, "-extract"),
		OPT_STR(OPT_IN, "-in"),
		OPT_STR(OPT_IN_PATH, "-in-path"),
		OPT_NONE(OPT_KEEP, "-keep"),
		OPT_STR(OPT_LOCK, "-lock"),
		OPT_STR(OPT_OUT, "-out"),
		OPT_STR(OPT_OUT_PATH, "-out-path"),
		OPT_INT(OPT_THREADS, "-threads")
	};
#undef OPT
	int status = 1;
	int result;
	int in_is_dir;
	int has_out;
	int out_is_dir;
	int cmd_accepts_out;
	struct rl_context ctx;
	int in_dir_fd;
	DIR *in_dir;
	int out_dir_fd;
	struct dirent *in_dir_entry;

	result = parse_opts(argc, argv, OPT_COUNT, opts);
	if (result < 0)
		return print_usage(argc, argv);

	in_is_dir = get_opt_defined(opts, OPT_IN_PATH);
	has_out = get_opt_defined(opts, OPT_OUT_PATH) || get_opt_defined(opts, OPT_OUT);
	out_is_dir = get_opt_defined(opts, OPT_OUT_PATH);

	cmd_accepts_out = get_opt_defined(opts, OPT_ENCRYPT) || get_opt_defined(opts, OPT_DECRYPT)
			|| get_opt_defined(opts, OPT_COMPRESS) || get_opt_defined(opts, OPT_EXTRACT);

	if (
			/* There must be exactly one <action> */
			(get_opt_defined(opts, OPT_ENCRYPT) + get_opt_defined(opts, OPT_DECRYPT)
				+ get_opt_defined(opts, OPT_COMPRESS) + get_opt_defined(opts, OPT_EXTRACT)
				+ get_opt_defined(opts, OPT_CHECK) + get_opt_defined(opts, OPT_CLEAN) != 1)
			/* -out-path and -out are disallowed if the <action> does not accept output */
			|| (!cmd_accepts_out && has_out)
			/* -autoclean requires an explicit or implicit -out or -out-path */
			|| (!cmd_accepts_out && get_opt_defined(opts, OPT_AUTOCLEAN))
			/* There must be exactly one of -in-path or -in */
			|| (get_opt_defined(opts, OPT_IN_PATH) + get_opt_defined(opts, OPT_IN) != 1)
			/* There must be at most one of -out-path or -out */
			|| (get_opt_defined(opts, OPT_OUT_PATH) + get_opt_defined(opts, OPT_OUT) > 1)
			/* If -in-path is specified then -out cannot be specified */
			|| (get_opt_defined(opts, OPT_IN_PATH) && get_opt_defined(opts, OPT_OUT))
			/* -cron requires -lock */
			|| (get_opt_defined(opts, OPT_CRON) && !get_opt_defined(opts, OPT_LOCK))
			/* The thread count must be > 0 */
			|| (get_opt_defined(opts, OPT_THREADS) && get_opt_int(opts, OPT_THREADS) <= 0))
		return print_usage(argc, argv);

	ctx.lock_fd = -1;

	if (get_opt_defined(opts, OPT_LOCK))
	{
		const char *lock_filename = get_opt_str(opts, OPT_LOCK);
		struct flock lck = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 0
		};

		ctx.lock_fd = open(lock_filename, DEFAULT_FILE_MODE);
		if (ctx.lock_fd < 0)
			goto fail_open_lock;

		result = fcntl(ctx.lock_fd, F_SETLK, &lck);
		if (result < 0)
		{
			/* Skip if failed to acquire the lock */
			status = 0;
			goto fail_lock_lock;
		}
	}

	ctx.pipeline_has_encrypt = get_opt_defined(opts, OPT_ENCRYPT);
	ctx.pipeline_has_decrypt = get_opt_defined(opts, OPT_DECRYPT);
	ctx.pipeline_has_compress = get_opt_defined(opts, OPT_ENCRYPT) || get_opt_defined(opts, OPT_COMPRESS);
	ctx.pipeline_has_extract = get_opt_defined(opts, OPT_DECRYPT) || get_opt_defined(opts, OPT_EXTRACT);
	ctx.pipeline_has_in_digest = get_opt_defined(opts, OPT_DECRYPT) || get_opt_defined(opts, OPT_CHECK);
	ctx.pipeline_has_out_digest = get_opt_defined(opts, OPT_ENCRYPT);

	ctx.pipeline = CRYPTO_PIPELINE_COUNT;
	if (ctx.pipeline_has_encrypt)
		ctx.pipeline = CRYPTO_PIPELINE_COMPRESS_ENCRYPT_DIGEST;
	else if (ctx.pipeline_has_decrypt)
		ctx.pipeline = CRYPTO_PIPELINE_DIGEST_DECRYPT_EXTRACT;
	else if (ctx.pipeline_has_compress)
		ctx.pipeline = CRYPTO_PIPELINE_COMPRESS;
	else if (ctx.pipeline_has_extract)
		ctx.pipeline = CRYPTO_PIPELINE_EXTRACT;
	else if (ctx.pipeline_has_in_digest)
		ctx.pipeline = CRYPTO_PIPELINE_DIGEST;

	if (ctx.pipeline_has_compress || ctx.pipeline_has_extract)
	{
		ctx.lzma_filter = LZMA_FILTER_LZMA2;
		ctx.lzma_check = LZMA_CHECK_CRC64;
		ctx.lzma_preset = 5 | LZMA_PRESET_EXTREME;
		ctx.lzma_threads = get_opt_defined(opts, OPT_THREADS) ? get_opt_int(opts, OPT_THREADS) : 1;
		ctx.lzma_mem_limit = UINT64_MAX;
		ctx.lzma_stream = (lzma_stream)LZMA_STREAM_INIT;

		if (ctx.pipeline_has_compress && !lzma_filter_encoder_is_supported(ctx.lzma_filter))
			goto fail_lzma_settings;

		if (!ctx.pipeline_has_extract && !lzma_filter_decoder_is_supported(ctx.lzma_filter))
			goto fail_lzma_settings;

		if (!lzma_check_is_supported(ctx.lzma_check))
			goto fail_lzma_settings;

		if (lzma_lzma_preset(&ctx.lzma_options, ctx.lzma_preset))
			goto fail_lzma_settings;
	}

	if (ctx.pipeline_has_encrypt || ctx.pipeline_has_decrypt)
	{
		const char *password;

		ctx.cipher = EVP_aes_256_cbc();
		ctx.hash = EVP_sha256();
		ctx.hash_rounds = 5;

		memset(ctx.salt, '\0', sizeof(ctx.salt));
		memcpy(ctx.salt, PASSWORD_SALT, mini(sizeof(ctx.salt), sizeof(PASSWORD_SALT)));

		OPENSSL_assert(EVP_CIPHER_key_length(ctx.cipher) == sizeof(ctx.key));
		OPENSSL_assert(EVP_CIPHER_iv_length(ctx.cipher) == sizeof(ctx.iv));

		password = ctx.pipeline_has_encrypt ? get_opt_str(opts, OPT_ENCRYPT) : get_opt_str(opts, OPT_DECRYPT);

		result = EVP_BytesToKey(ctx.cipher, ctx.hash,
				ctx.salt,
				(unsigned char *)password, strlen(password),
				ctx.hash_rounds, ctx.key, ctx.iv);

		OPENSSL_assert(result == sizeof(ctx.key));

		ctx.cipher_ctx = EVP_CIPHER_CTX_new();
		if (!ctx.cipher_ctx)
			goto fail_cipher_ctx_new;
	}

	if (ctx.pipeline_has_in_digest || ctx.pipeline_has_out_digest)
	{
		ctx.digest_type = EVP_sha256();
		ctx.digest_ctx = EVP_MD_CTX_new();
		if (!ctx.digest_ctx)
			goto fail_digest_ctx_new;
	}

	in_dir_fd = AT_FDCWD;

	if (in_is_dir)
	{
		in_dir_fd = open(get_opt_str(opts, OPT_IN_PATH), O_RDONLY | O_DIRECTORY);
		if (in_dir_fd < 0)
			goto fail_open_in;

		in_dir = fdopendir(in_dir_fd);
		if (!in_dir)
		{
			close(in_dir_fd);
			goto fail_open_in;
		}
	}

	out_dir_fd = AT_FDCWD;

	if (cmd_accepts_out)
	{
		if (!has_out)
		{
			if (in_is_dir)
			{
				out_dir_fd = dup(in_dir_fd);
				if (out_dir_fd < 0)
					goto fail_open_out;

				out_is_dir = 1;
			}
			else
				out_is_dir = 0;
		}
		else if (out_is_dir)
		{
			out_dir_fd = open(get_opt_str(opts, OPT_OUT_PATH), O_RDONLY | O_DIRECTORY);
			if (out_dir_fd < 0)
				goto fail_open_out;
		}
	}

	int first_loop = 1;
	while ((!in_is_dir && first_loop)
			|| (in_is_dir && (in_dir_entry = readdir(in_dir))))
	{
		const char *in_filename = NULL;
		char out_filename_buf[4096];
		const char *out_filename = NULL;
		char digest_filename_buf[4096];
		FILE *infp = NULL, *outfp = NULL, *digestfp = NULL;

		first_loop = 0;

		in_filename = in_is_dir ? in_dir_entry->d_name : get_opt_str(opts, OPT_IN);

		if (cmd_accepts_out)
		{
			if (out_is_dir)
			{
				build_out_filename(&ctx, sizeof(out_filename_buf), out_filename_buf, my_basename(in_filename), 0);
				out_filename = out_filename_buf;
			}
			else if (has_out)
				out_filename = get_opt_str(opts, OPT_OUT);
			else
			{
				build_out_filename(&ctx, sizeof(out_filename_buf), out_filename_buf, in_filename, 0);
				out_filename = out_filename_buf;
			}
		}

		if (ctx.pipeline_has_in_digest)
		{
			build_out_filename(&ctx, sizeof(digest_filename_buf), digest_filename_buf, in_filename, 1);
			result = open_files(in_dir_fd, digest_filename_buf, -1, NULL, &digestfp, NULL);
			if (result < 0)
				goto fail_digest;
		}
		else if (ctx.pipeline_has_out_digest && cmd_accepts_out)
		{
			build_out_filename(&ctx, sizeof(digest_filename_buf), digest_filename_buf, out_filename, 1);
			result = open_files(-1, NULL, out_dir_fd, digest_filename_buf, NULL, &digestfp);
			if (result < 0)
				goto fail_digest;
		}

		result = open_files(in_dir_fd, in_filename, out_dir_fd, out_filename, &infp, &outfp);
		if (result < 0)
		{
			if (!in_is_dir)
				goto fail_open;
			continue;
		}

		result = do_crypto(&ctx, infp, outfp, digestfp);

		if (outfp)
			fclose(outfp);
		if (infp)
			fclose(infp);

fail_open:
		if (digestfp)
			fclose(digestfp);

fail_digest:
		if (cmd_accepts_out)
		{
			if (result == 0)
			{
				if (!get_opt_defined(opts, OPT_KEEP))
				{
					unlinkat(in_dir_fd, in_filename, 0);
					if (ctx.pipeline_has_in_digest)
						unlinkat(in_dir_fd, digest_filename_buf, 0);
				}
			}
			else
			{
				unlinkat(out_dir_fd, out_filename, 0);
				if (ctx.pipeline_has_out_digest)
					unlinkat(out_dir_fd, digest_filename_buf, 0);
			}
		}

		if (result < 0)
			goto fail_crypto;
	}

	status = 0;	

fail_crypto:
	if (cmd_accepts_out && out_is_dir)
		close(out_dir_fd);

fail_open_out:
	if (in_is_dir)
		closedir(in_dir);

fail_open_in:
	if (ctx.pipeline_has_in_digest || ctx.pipeline_has_out_digest)
		EVP_MD_CTX_free(ctx.digest_ctx);

fail_digest_ctx_new:
	if (ctx.pipeline_has_encrypt || ctx.pipeline_has_decrypt)
		EVP_CIPHER_CTX_free(ctx.cipher_ctx);

fail_cipher_ctx_new:
fail_lzma_settings:
	if (ctx.lock_fd >= 0)
	{
		struct flock lck = {
			.l_type = F_UNLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 0
		};
		fcntl(ctx.lock_fd, F_SETLK, &lck);
	}

fail_lock_lock:
	if (ctx.lock_fd >= 0)
		close(ctx.lock_fd);

fail_open_lock:
	printf("%s\n", (status == 0) ? "OK" : "Critical");

	return status;
}
