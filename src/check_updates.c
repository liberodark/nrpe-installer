#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <gio/gio.h>
#include <glib.h>
#include <gmodule.h>

#define I_KNOW_THE_PACKAGEKIT_GLIB2_API_IS_SUBJECT_TO_CHANGE 1

#include <packagekit-glib2/packagekit.h>

#define DEFAULT_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))


/***** Options handling *****/

enum opt_id
{
	OPT_C = 0,
	OPT_CRON,
	OPT_LOCK,
	OPT_SECURITY_UPDATE,
	OPT_UPDATE,
	OPT_W,
	OPT_Y,
	OPT_COUNT
};

enum opt_type
{
	OPT_TYPE_INVAL = 0,
	OPT_TYPE_NONE,
	OPT_TYPE_INT,
	OPT_TYPE_STR,
	OPT_TYPE_CRON
};

struct opt_data_cron
{
	int M;
	int H;
	int d;
	int m;
};

struct opt
{
	enum opt_type type;
	const char *name;
	unsigned int defined : 1;
	union {
		int as_int;
		const char *as_str;
		struct opt_data_cron as_cron;
	} data;
};

static inline const char *skip_spaces(const char *p) {
	while (isspace(*p))
		p++;

	return p;
}

static int parse_opts_helper(int argc, char **argv, struct opt *opts)
{
	int result;
	int i;
	int arg_count = 0;

	for (struct opt *opt = opts; opt->type != OPT_TYPE_INVAL; opt++)
	{
		opt->defined = 0;
		opt->data.as_str = NULL;
	}

	for (i = 0; i < argc; i++)
	{
		char *arg = argv[i];
		int matched = 0;

		for (struct opt *opt = opts; opt->type != OPT_TYPE_INVAL; opt++)
		{
			result = strcmp(arg, opt->name);
			if (result != 0)
				continue;

			matched = 1;
			/* Reset a redefined opt */
			opt->defined = 0;

			if (opt->type != OPT_TYPE_NONE)
			{
				if (i >= argc - 1)
					return -1;

				opt->data.as_str = argv[++i];
			}
			else
				opt->data.as_str = "";
		}

		if (!matched)
			return -1;
	}

	arg_count = i;

	for (struct opt *opt = opts; opt->type != OPT_TYPE_INVAL; opt++)
	{
		if (!opt->data.as_str)
			continue;

		switch (opt->type)
		{
			case OPT_TYPE_INVAL:
			case OPT_TYPE_NONE:
			case OPT_TYPE_STR:
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

			case OPT_TYPE_CRON:
			{
				const char *hardcoded[] = {
					"@hourly",   "0 * * *",
					"@daily",    "0 0 * *",
					"@midnight", "0 0 * *",
					"@monthly",  "0 0 1 *",
					"@annually", "0 0 1 1"
					"@yearly",   "0 0 1 1"
				};
				const char *origp, *p;
				char *endp;
				int params[4];
				long int n;

				origp = opt->data.as_str;

				for (size_t j = 0; j < ARRAY_SIZE(hardcoded); j += 2)
				{
					if (strcmp(origp, hardcoded[j]) == 0)
					{
						origp = hardcoded[j + 1];
						break;
					}
				}

				p = origp;

				for (size_t j = 0; j < ARRAY_SIZE(params); j++)
				{
					params[j] = 0;

					if (p != origp
							&& !isspace(*p))
						return -1;

					p = skip_spaces(p);
					if (!*p)
						return -1;

					if (*p == '*')
					{
						params[j] = -1;
						p++;

						if (*p != '/')
							continue;
						p++;
					}

					n = strtol(p, &endp, 10);
					if (endp == p || n < 0)
						return -1;
					p = endp;

					if (params[j] < 0)
						n = -n;

					params[j] = n;
				}

				p = skip_spaces(p);
				if (*p)
					return -1;

				if (params[0] > 59
						|| params[1] > 23
						|| params[2] == 0 || params[2] > 31
						|| params[3] == 0 || params[3] > 12)
					return -1;

				opt->data.as_cron.M = params[0];
				opt->data.as_cron.H = params[1];
				opt->data.as_cron.d = params[2];
				opt->data.as_cron.m = params[3];
				break;
			}
		}

		opt->defined = 1;
	}

	return arg_count;
}

struct opt *parse_opts(int argc, char **argv, struct opt *tpl)
{
	int count;

	if (argc < 1 || !argv)
		return NULL;

	argc--;
	argv++;

	count = parse_opts_helper(argc, argv, tpl);
	if (count < 0)
		return NULL;

	return tpl;
}

int get_opt_defined(struct opt *opts, enum opt_id id)
{
	if (id >= OPT_COUNT)
		return 0;

	return opts[id].defined;
}

int get_opt_int(struct opt *opts, enum opt_id id)
{
	if (id >= OPT_COUNT)
		return INT_MAX;

	if (!opts[id].defined || opts[id].type != OPT_TYPE_INT)
		return INT_MAX;

	return opts[id].data.as_int;
}

const char *get_opt_str(struct opt *opts, enum opt_id id)
{
	if (id >= OPT_COUNT)
		return NULL;

	if (!opts[id].defined || opts[id].type != OPT_TYPE_STR)
		return NULL;

	return opts[id].data.as_str;
}

struct opt_data_cron *get_opt_cron(struct opt *opts, enum opt_id id)
{
	if (id >= OPT_COUNT)
		return NULL;

	if (!opts[id].defined || opts[id].type != OPT_TYPE_CRON)
		return NULL;

	return &opts[id].data.as_cron;
}


/***** Frontend *****/

#define LOG(...) fprintf(stderr, __VA_ARGS__)

static inline int clampi(int n, int a, int b) {
	return n < a ? a : n > b ? b : n;
}

static void handle_sig(int num, void (*handler)(int))
{
	struct sigaction act;

	act.sa_handler = handler;
	sigfillset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction(num, &act, NULL);
}

static gint pkg_cmp_by_id(gconstpointer a, gconstpointer b)
{
	return strcmp(pk_package_get_id(*(PkPackage **)a),
			pk_package_get_id(*(PkPackage **)b));
}

static gint upd_cmp_by_pkg_id(gconstpointer a, gconstpointer b)
{
	return strcmp(pk_update_detail_get_package_id(*(PkUpdateDetail **)a),
			pk_update_detail_get_package_id(*(PkUpdateDetail **)b));
}

struct pkg_context
{
	gboolean is_cancellable;
	GCancellable *cancellable;
};

static void progress_cb(PkProgress *progress, PkProgressType type, gpointer user_data)
{
	struct pkg_context *ctx = (struct pkg_context *)user_data;

	switch(type)
	{
		case PK_PROGRESS_TYPE_PACKAGE_ID:
		{
			const gchar *pkg_id = pk_progress_get_package_id(progress);

			LOG("Package ID: %s\n", pkg_id);
			break;
		}

		case PK_PROGRESS_TYPE_TRANSACTION_ID:
		{
			const gchar *trans_id = pk_progress_get_transaction_id(progress);

			LOG("Transaction ID: %s\n", trans_id);
			break;
		}

		case PK_PROGRESS_TYPE_PERCENTAGE:
		{
			gint pct = pk_progress_get_percentage(progress);

			pct = clampi(pct, 0, 100);
			LOG("Progress: %d%%\n", pct);
			break;
		}

		case PK_PROGRESS_TYPE_ALLOW_CANCEL:
		{
			gboolean allow_cancel = pk_progress_get_allow_cancel(progress);

			ctx->is_cancellable = allow_cancel;

			LOG("Allow cancel: %s\n", allow_cancel ? "true" : "false");
			break;
		}

		case PK_PROGRESS_TYPE_STATUS:
		{
			PkStatusEnum status = pk_progress_get_status(progress);
			const gchar *status_str = pk_status_enum_to_string(status);

			LOG("Status: %s\n", status_str);
			break;
		}

		case PK_PROGRESS_TYPE_ROLE:
		{
			PkRoleEnum role = pk_progress_get_role(progress);
			const gchar *role_str = pk_role_enum_to_string(role);

			LOG("Role: %s\n", role_str);
			break;
		}

		case PK_PROGRESS_TYPE_CALLER_ACTIVE:
		{
			gboolean caller_active = pk_progress_get_caller_active(progress);

			LOG("Caller active: %s\n", caller_active ? "true" : "false");
			break;
		}

		case PK_PROGRESS_TYPE_ELAPSED_TIME:
		{
			guint elapsed_time_sec = pk_progress_get_elapsed_time(progress);

			LOG("Elapsed time: %u sec\n", elapsed_time_sec);
			break;
		}

		case PK_PROGRESS_TYPE_REMAINING_TIME:
		{
			guint remaining_time_sec = pk_progress_get_remaining_time(progress);

			LOG("Remaining time: %u sec\n", remaining_time_sec);
			break;
		}

		case PK_PROGRESS_TYPE_SPEED:
		{
			guint speed_bps = pk_progress_get_speed(progress);

			if (speed_bps == 0)
				LOG("Speed: unknown\n");
			else
				LOG("Speed: %u kiBps (%u kbps)\n", speed_bps / 8 / 1024, speed_bps / 1024);
			break;
		}

		case PK_PROGRESS_TYPE_DOWNLOAD_SIZE_REMAINING:
		{
			guint64 download_size_remaining = pk_progress_get_download_size_remaining(progress);

			LOG("Download size remaining: %"PRIu64" kiB\n", download_size_remaining / 1024);
			break;
		}

		case PK_PROGRESS_TYPE_UID:
		{
			guint uid = pk_progress_get_uid(progress);

			LOG("User ID: %u\n", uid);
			break;
		}

		case PK_PROGRESS_TYPE_PACKAGE:
		{
			PkPackage *pkg = pk_progress_get_package(progress);
			const gchar *pkg_id = pk_package_get_id(pkg);
			gchar *pkg_name = pk_package_id_to_printable(pkg_id);

			LOG("Package: %s\n", pkg_name);
			g_free(pkg_name);
			break;
		}

		case PK_PROGRESS_TYPE_ITEM_PROGRESS:
		{
			PkItemProgress *item = pk_progress_get_item_progress(progress);
			PkStatusEnum status = pk_item_progress_get_status(item);
			const gchar *status_str = pk_status_enum_to_string(status);
			guint pct = pk_item_progress_get_percentage(item);
			const gchar *pkg_id = pk_item_progress_get_package_id(item);
			gchar *pkg_name = pk_package_id_to_printable(pkg_id);

			pct = clampi(pct, 0, 100);
			LOG("[%s(%u): %u%%] %s\n", status_str, status, pct, pkg_name);
			g_free(pkg_name);
			break;
		}

		case PK_PROGRESS_TYPE_TRANSACTION_FLAGS:
		{
			PkBitfield trans_flags = pk_progress_get_transaction_flags(progress);
			gchar *trans_flags_str = pk_transaction_flag_bitfield_to_string(trans_flags);

			LOG("Transaction flags: %s\n", trans_flags_str);
			g_free(trans_flags_str);
			break;
		}

		case PK_PROGRESS_TYPE_INVALID:
			break;
	}
}

static struct pkg_context ctx;

static void sig_handler(int num)
{
	if (!ctx.is_cancellable)
	{
		LOG("Received signal %d, but the current step is not cancellable.\n", num);
		return;
	}

	LOG("Received signal %d, terminating...\n", num);

	g_cancellable_cancel(ctx.cancellable);
	exit(1);
}

int print_usage(int argc, char **argv)
{
	LOG("Usage: %s [-lock <lock_file> [-cron <cron_spec>]] [-w <warn_treshold>] [-c <crit_treshold>] [-security-update] [-update] [-y]\n", (argc >= 1) ? argv[0] : "check_pkg");
	return 1;
}

static inline int tm_fix_cron(int tm_field, int cron_field) {
	if (cron_field < 0)
		return tm_field - tm_field % -cron_field;

	return cron_field;
}

int main(int argc, char **argv)
{
#define OPT_NONE(e, n) [e] = { .type = OPT_TYPE_NONE, .name = n }
#define OPT_STR(e, n) [e] = { .type = OPT_TYPE_STR, .name = n }
#define OPT_INT(e, n) [e] = { .type = OPT_TYPE_INT, .name = n }
#define OPT_CRON(e, n) [e] = { .type = OPT_TYPE_CRON, .name = n }
#define OPT_END() [OPT_COUNT] = { .type = OPT_TYPE_INVAL, .name = NULL }
	struct opt opt_tpl[] = {
		OPT_INT(OPT_C, "-c"),
		OPT_CRON(OPT_CRON, "-cron"),
		OPT_STR(OPT_LOCK, "-lock"),
		OPT_NONE(OPT_SECURITY_UPDATE, "-security-update"),
		OPT_NONE(OPT_UPDATE, "-update"),
		OPT_INT(OPT_W, "-w"),
		OPT_NONE(OPT_Y, "-y"),
		OPT_END()
	};
#undef OPT_END
#undef OPT_CRON
#undef OPT_INT
#undef OPT_STR
#undef OPT_NONE
	int status = 2;
	const char *reason = "N/A";
	int result = -1;
	time_t now;
	struct opt *opts;
	int lock_fd;
	int warn_treshold = INT_MAX;
	int crit_treshold = INT_MAX;
	int must_upd_pkg = 0;
	int must_upd_sec_pkg = 0;
	int ask_confirm = 0;
	PkClient *cli;
	GError *gerror = NULL;
	PkResults *pk_results;
	GPtrArray *pkgs;
	GPtrArray *pkg_ids;
	GPtrArray *upds;
	size_t total_upd_count = 0;
	size_t sec_upd_count = 0;
	const char *panic_str;
	gchar *nagios_is_a_useless_pile_of_shit = g_strdup("Security updates:\n");

	now = time(NULL);

	opts = parse_opts(argc, argv, opt_tpl);
	if (!opts)
		return print_usage(argc, argv);


	if (
			/* -cron requires -lock */
			get_opt_defined(opts, OPT_CRON) && !get_opt_defined(opts, OPT_LOCK))
		return print_usage(argc, argv);

	lock_fd = -1;

	if (get_opt_defined(opts, OPT_LOCK))
	{
		const char *lock_filename = get_opt_str(opts, OPT_LOCK);
		struct flock lck = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 0
		};

		lock_fd = open(lock_filename, O_CREAT | O_RDWR, DEFAULT_FILE_MODE);
		if (lock_fd < 0)
			goto fail_open_lock;

		result = fcntl(lock_fd, F_SETLK, &lck);
		if (result < 0)
		{
			/* Skip if failed to acquire the lock */
			status = 0;
			goto fail_lock_lock;
		}

		if (get_opt_defined(opts, OPT_CRON))
		{
			ssize_t ssresult;
			int len;
			time_t prev_time;
			time_t cur_time;
			char buf[32];
			char *endp;

			prev_time = -1;
			cur_time = now;

			ssresult = read(lock_fd, buf, sizeof(buf) - 1);
			if (ssresult > 0)
			{
				buf[ssresult] = '\0';

				prev_time = strtoll(buf, &endp, 10);
				if (endp == buf || *endp)
					prev_time = -1;
			}

			if (prev_time >= 0)
			{
				struct opt_data_cron *dcron = get_opt_cron(opts, OPT_CRON);
				struct tm tm = *localtime(&cur_time);
				time_t last_period;
				int can_exec;

				tm.tm_sec = 0;
				tm.tm_min = tm_fix_cron(tm.tm_min, dcron->M);
				tm.tm_hour = tm_fix_cron(tm.tm_hour, dcron->H);
				tm.tm_mday = tm_fix_cron(tm.tm_mday, dcron->d);
				tm.tm_mon = tm_fix_cron(tm.tm_mon, dcron->m - 1);

				last_period = mktime(&tm);

				can_exec = last_period <= cur_time && prev_time < last_period;
				if (!can_exec)
				{
					status = 0;
					printf("UPDATE OK | Cron timeout not expired\n");
					goto fail_cron;
				}
			}

			lseek(lock_fd, 0, SEEK_SET);
			ftruncate(lock_fd, 0);
			len = snprintf(buf, sizeof(buf), "%lld", (long long int)cur_time);
			write(lock_fd, buf, len);
		}
	}

	if (get_opt_defined(opts, OPT_W))
		warn_treshold = get_opt_int(opts, OPT_W);

	if (get_opt_defined(opts, OPT_C))
		crit_treshold = get_opt_int(opts, OPT_C);

	must_upd_pkg = get_opt_defined(opts, OPT_UPDATE);
	must_upd_sec_pkg = get_opt_defined(opts, OPT_SECURITY_UPDATE);
	ask_confirm = !get_opt_defined(opts, OPT_Y);

	ctx.is_cancellable = TRUE;
	ctx.cancellable = g_cancellable_new();

	handle_sig(SIGHUP, sig_handler);
	handle_sig(SIGINT, sig_handler);
	handle_sig(SIGQUIT, sig_handler);
	handle_sig(SIGTERM, sig_handler);

	cli = pk_client_new();
	if (!cli)
	{
		reason = "Failed to create a new PackageKit client";
		goto fail_new_cli;
	}

	pk_client_set_interactive(cli, TRUE);

	pk_results = pk_client_refresh_cache(cli, TRUE, ctx.cancellable, progress_cb, &ctx, &gerror);
	if (!pk_results)
	{
		reason = "Failed to refresh the update list";
		goto fail;
	}

	g_cancellable_reset(ctx.cancellable);

	pk_results = pk_client_get_updates(cli,
			pk_bitfield_from_enums(PK_FILTER_ENUM_NONE, -1),
			ctx.cancellable, progress_cb, &ctx, &gerror);
	if (!pk_results)
	{
		reason = "Failed to get the update list";
		goto fail;
	}

	g_cancellable_reset(ctx.cancellable);

	pkgs = pk_results_get_package_array(pk_results);
	g_object_unref(pk_results);
	if (!pkgs)
	{
		reason = "Failed to get packages from the update list";
		goto fail;
	}

	if (pkgs->len == 0)
	{
		/* Short path */
		g_ptr_array_unref(pkgs);
		LOG("Everything is up to date.\n");
		goto done;
	}

	g_ptr_array_sort(pkgs, pkg_cmp_by_id);

	total_upd_count = pkgs->len;

	pkg_ids = g_ptr_array_sized_new(total_upd_count + 1);

	for (size_t i = 0; i < pkgs->len; i++)
	{
		PkPackage *pkg = (PkPackage *)g_ptr_array_index(pkgs, i);
		const gchar *pkg_id = pk_package_get_id(pkg);

		g_ptr_array_add(pkg_ids, (gchar *)pkg_id);
	}

	g_ptr_array_add(pkg_ids, NULL);

	pk_results = pk_client_get_update_detail(cli, (gchar **)pkg_ids->pdata, ctx.cancellable, progress_cb, &ctx, &gerror);
	ctx.is_cancellable = TRUE;
	g_ptr_array_unref(pkg_ids);
	if (!pk_results)
	{
		reason = "Failed to get update detail";
		goto fail;
	}

	g_cancellable_reset(ctx.cancellable);

	upds = pk_results_get_update_detail_array(pk_results);
	g_object_unref(pk_results);
	if (!upds)
	{
		reason = "Failed to extract update detail";
		goto fail;
	}

	g_ptr_array_sort(upds, upd_cmp_by_pkg_id);

	if (must_upd_pkg || must_upd_sec_pkg)
	{
		pkg_ids = g_ptr_array_sized_new(total_upd_count + 1);
		LOG("The following packages will be updated:\n");
	}
	else
		LOG("The following packages are security updates:\n");

	for (size_t i = 0, i_upd = 0; i < pkgs->len; i++)
	{
		PkPackage *pkg = (PkPackage *)g_ptr_array_index(pkgs, i);
		const gchar *pkg_id = pk_package_get_id(pkg);
		PkInfoEnum pkg_info = pk_package_get_info(pkg);
		PkUpdateDetail *upd;
		const gchar *upd_pkg_id;
		gchar **cve_urls;
		const gchar *changelog;
		int have_upd_detail = 0;
		int add_pkg = 0;
		int is_sec = 0;
		long int dummy;

		while (i_upd < upds->len)
		{
			upd = (PkUpdateDetail *)g_ptr_array_index(upds, i_upd);
			upd_pkg_id = pk_update_detail_get_package_id(upd);
			cve_urls = pk_update_detail_get_cve_urls(upd);
			changelog = pk_update_detail_get_changelog(upd);
			int d;

			i_upd++;
			d = strcmp(pkg_id, upd_pkg_id);
			if (d == 0)
			{
				have_upd_detail = 1;
				break;
			}
			else if (d < 0)
			{
				i_upd--;
				break;
			}
			else if (d > 0)
			{
				gchar *pkg_name;

				pkg_name = pk_package_id_to_printable(upd_pkg_id);
				LOG("WARN: Unexpectedly got update detail for non-requested package %s\n", pkg_name);
				g_free(pkg_name);
			}
		}

		if (!have_upd_detail)
		{
			gchar *pkg_name;

			pkg_name = pk_package_id_to_printable(pkg_id);
			LOG("WARN: Missing update detail for package %s\n", pkg_name);
			g_free(pkg_name);
		}

		if (must_upd_pkg)
			add_pkg = 1;

		if (have_upd_detail
				&& ((cve_urls && cve_urls[0])
					|| (changelog && strstr(changelog, "CVE-"))
					|| (pkg_info & PK_INFO_ENUM_SECURITY)))
			is_sec = 1;

		if (is_sec)
		{
			sec_upd_count++;

			if (must_upd_sec_pkg)
				add_pkg = 1;
		}

		if (is_sec || add_pkg)
		{
			gchar *pkg_name;
			gchar *s1, *s2;

			pkg_name = pk_package_id_to_printable(pkg_id);
			s1 = g_strdup_printf("%s%s\n", pkg_name, is_sec ? " (SECURITY)" : (have_upd_detail ? "" : " (\?\?\?)"));
			g_free(pkg_name);

			LOG("%s", s1);

			s2 = g_strconcat(nagios_is_a_useless_pile_of_shit, s1, NULL);
			g_free(s1);
			g_free(nagios_is_a_useless_pile_of_shit);
			nagios_is_a_useless_pile_of_shit = s2;

			if (add_pkg)
				g_ptr_array_add(pkg_ids, (gchar *)pkg_id);
		}
	}

	g_ptr_array_unref(upds);

	if ((must_upd_pkg && total_upd_count == 0)
			|| (must_upd_sec_pkg && sec_upd_count == 0)
			|| (!must_upd_pkg && !must_upd_sec_pkg && sec_upd_count == 0))
	{
		gchar *s1, *s2;

		s1 = "(none)\n";

		LOG("%s", s1);

		s2 = g_strconcat(nagios_is_a_useless_pile_of_shit, s1, NULL);
		g_free(nagios_is_a_useless_pile_of_shit);
		nagios_is_a_useless_pile_of_shit = s2;
	}

	if (must_upd_pkg || must_upd_sec_pkg)
	{
		int got_confirm = 1;

		if (pkg_ids->len == 0)
		{
			/* Short path */
			g_ptr_array_unref(pkg_ids);
			g_ptr_array_unref(pkgs);
			LOG("Everything is up to date.\n");
			goto done;
		}

		if (ask_confirm)
		{
			char c = 0;

			while (c != 'y' && c != 'n')
			{
				printf("\nProceed with installation? [y/n] ");
				scanf("%c", &c);
			}

			got_confirm = c == 'y';
		}

		if (got_confirm)
		{
			g_ptr_array_add(pkg_ids, NULL);

			pk_results = pk_client_update_packages(cli,
					pk_bitfield_from_enums(PK_TRANSACTION_FLAG_ENUM_NONE, -1),
					(gchar **)pkg_ids->pdata, ctx.cancellable, progress_cb, &ctx, &gerror);
		}

		ctx.is_cancellable = TRUE;
		g_ptr_array_unref(pkg_ids);
		g_ptr_array_unref(pkgs);

		if (!got_confirm)
		{
			reason = "Cancelled by user";
			goto fail;
		}

		if (!pk_results)
		{
			reason = "Failed to update packages";
			goto fail;
		}

		g_cancellable_reset(ctx.cancellable);
	}


done:
	panic_str = "OK";
	status = 0;
	if (sec_upd_count >= crit_treshold)
	{
		panic_str = "Critical";
		status = 2;
	}
	else if (sec_upd_count >= warn_treshold)
	{
		panic_str = "Warning";
		status = 1;
	}

	printf("UPDATE %s - Security-Update = %zu | 'Total Update' = %zu\n%s", panic_str, sec_upd_count, total_upd_count, nagios_is_a_useless_pile_of_shit);
	g_free(nagios_is_a_useless_pile_of_shit);

	result = 0;

fail:
	g_object_unref(cli);
	g_object_unref(ctx.cancellable);

fail_new_cli:
	if (result < 0)
	{
		const char *gerror_msg = (gerror && gerror->message) ? gerror->message : "";

		status = 2;
		printf("UPDATE Critical | An error occurred: %s%s%s\n", reason, gerror_msg[0] ? ": " : "", gerror_msg);
	}

	if (gerror)
		g_error_free(gerror);

fail_cron:
	if (lock_fd >= 0)
	{
		struct flock lck = {
			.l_type = F_UNLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 0
		};
		fcntl(lock_fd, F_SETLK, &lck);
	}

fail_lock_lock:
	if (lock_fd >= 0)
		close(lock_fd);

fail_open_lock:
	return status;
}
