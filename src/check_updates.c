#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <gmodule.h>

#define I_KNOW_THE_PACKAGEKIT_GLIB2_API_IS_SUBJECT_TO_CHANGE 1

#include <packagekit-glib2/packagekit.h>


enum opt_id
{
	OPT_C = 0,
	OPT_DETAILS,
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
	OPT_TYPE_STR
};

struct opt
{
	enum opt_type type;
	const char *name;
	unsigned int defined : 1;
	union {
		int as_int;
		const char *as_str;
	} data;
};

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

int print_usage(int argc, char **argv)
{
	fprintf(stderr, "Usage: %s [-w <warn_treshold>] [-c <crit_treshold>] [-security-update] [-update]\n", (argc >= 1) ? argv[0] : "check_pkg");
	return 1;
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

static void pk_progress_cb(PkProgress *progress, PkProgressType type, gpointer user_data)
{
	switch(type)
	{
		case PK_PROGRESS_TYPE_PACKAGE_ID:
		{
			const gchar *pkg_id = pk_progress_get_package_id(progress);

			printf("Package ID: %s\n", pkg_id);
			break;
		}

		case PK_PROGRESS_TYPE_TRANSACTION_ID:
		{
			const gchar *trans_id = pk_progress_get_transaction_id(progress);

			printf("Transaction ID: %s\n", trans_id);
			break;
		}

		case PK_PROGRESS_TYPE_PERCENTAGE:
		{
			gint pct = pk_progress_get_percentage(progress);

			if (pct < 0 || pct > 100)
				printf("Progress: unknown\n");
			else
				printf("Progress: %d%%\n", pct);
			break;
		}

		case PK_PROGRESS_TYPE_ALLOW_CANCEL:
		{
			gboolean allow_cancel = pk_progress_get_allow_cancel(progress);

			printf("Allow cancel: %s\n", allow_cancel ? "true" : "false");
			break;
		}

		case PK_PROGRESS_TYPE_STATUS:
		{
			PkStatusEnum status = pk_progress_get_status(progress);
			const gchar *status_str = pk_status_enum_to_string(status);

			printf("Status: %s\n", status_str);
			break;
		}

		case PK_PROGRESS_TYPE_ROLE:
		{
			PkRoleEnum role = pk_progress_get_role(progress);
			const gchar *role_str = pk_role_enum_to_string(role);

			printf("Role: %s\n", role_str);
			break;
		}

		case PK_PROGRESS_TYPE_CALLER_ACTIVE:
		{
			gboolean caller_active = pk_progress_get_caller_active(progress);

			printf("Caller active: %s\n", caller_active ? "true" : "false");
			break;
		}

		case PK_PROGRESS_TYPE_ELAPSED_TIME:
		{
			guint elapsed_time_sec = pk_progress_get_elapsed_time(progress);

			printf("Elapsed time: %u sec\n", elapsed_time_sec);
			break;
		}

		case PK_PROGRESS_TYPE_REMAINING_TIME:
		{
			guint remaining_time_sec = pk_progress_get_remaining_time(progress);

			printf("Remaining time: %u sec\n", remaining_time_sec);
			break;
		}

		case PK_PROGRESS_TYPE_SPEED:
		{
			guint speed_bps = pk_progress_get_speed(progress);

			if (speed_bps == 0)
				printf("Speed: unknown\n");
			else
				printf("Speed: %u kBps (%u kbps)\n", speed_bps / 8 / 1024, speed_bps / 1024);
			break;
		}

		case PK_PROGRESS_TYPE_DOWNLOAD_SIZE_REMAINING:
		{
			guint64 download_size_remaining = pk_progress_get_download_size_remaining(progress);

			printf("Download size remaining: %"PRIu64" kB\n", download_size_remaining / 1024);
			break;
		}

		case PK_PROGRESS_TYPE_UID:
		{
			guint uid = pk_progress_get_uid(progress);

			printf("User ID: %u\n", uid);
			break;
		}

		case PK_PROGRESS_TYPE_PACKAGE:
		{
			PkPackage *pkg = pk_progress_get_package(progress);
			const gchar *pkg_id = pk_package_get_id(pkg);
			gchar *pkg_name = pk_package_id_to_printable(pkg_id);

			printf("Current package: %s\n", pkg_name);
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

			printf("[%s] %s: %u%%\n", status_str, pkg_name, pct);
			break;
		}

		case PK_PROGRESS_TYPE_TRANSACTION_FLAGS:
		{
			PkBitfield trans_flags = pk_progress_get_transaction_flags(progress);
			const gchar *trans_flags_str = pk_transaction_flag_enum_to_string(trans_flags);

			printf("Transaction flags: %s\n", trans_flags_str);
			break;
		}

		case PK_PROGRESS_TYPE_INVALID:
			break;
	}
}

int main(int argc, char **argv)
{
#define OPT_NONE(e, n) [e] = { .type = OPT_TYPE_NONE, .name = n }
#define OPT_STR(e, n) [e] = { .type = OPT_TYPE_STR, .name = n }
#define OPT_INT(e, n) [e] = { .type = OPT_TYPE_INT, .name = n }
#define OPT_END() [OPT_COUNT] = { .type = OPT_TYPE_INVAL, .name = NULL }
	struct opt opt_tpl[] = {
		OPT_INT(OPT_C, "-c"),
		OPT_NONE(OPT_DETAILS, "-details"),
		OPT_NONE(OPT_SECURITY_UPDATE, "-security-update"),
		OPT_NONE(OPT_UPDATE, "-update"),
		OPT_INT(OPT_W, "-w"),
		OPT_NONE(OPT_Y, "-y"),
		OPT_END()
	};
#undef OPT_END
#undef OPT_INT
#undef OPT_STR
#undef OPT_NONE
	int status;
	const char *reason = "N/A";
	int result = -1;
	struct opt *opts;
	int warn_treshold = INT_MAX;
	int crit_treshold = INT_MAX;
	int must_upd_pkg = 0;
	int must_upd_sec_pkg = 0;
	PkClient *cli;
	GError *gerror = NULL;
	PkResults *pk_results;
	GPtrArray *pkgs;
	GPtrArray *pkg_ids;
	GPtrArray *upds;
	size_t total_upd_count = 0;
	size_t sec_upd_count = 0;
	const char *panic_str;

	opts = parse_opts(argc, argv, opt_tpl);
	if (!opts)
		return print_usage(argc, argv);

	if (get_opt_defined(opts, OPT_W))
		warn_treshold = get_opt_int(opts, OPT_W);

	if (get_opt_defined(opts, OPT_C))
		crit_treshold = get_opt_int(opts, OPT_C);

	must_upd_pkg = get_opt_defined(opts, OPT_UPDATE);
	must_upd_sec_pkg = get_opt_defined(opts, OPT_SECURITY_UPDATE);

	cli = pk_client_new();
	if (!cli)
	{
		reason = "Failed to create a new PackageKit client";
		goto fail_new_cli;
	}

	pk_results = pk_client_get_updates(cli, PK_FILTER_ENUM_NONE, NULL, pk_progress_cb, NULL, &gerror);
	if (!pk_results)
	{
		reason = "Failed to get the update list";
		goto fail;
	}

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

	pk_results = pk_client_get_update_detail(cli, (gchar **)pkg_ids->pdata, NULL, pk_progress_cb, NULL, &gerror);
	g_ptr_array_unref(pkg_ids);
	if (!pk_results)
	{
		reason = "Failed to get update detail";
		goto fail;
	}

	upds = pk_results_get_update_detail_array(pk_results);
	g_object_unref(pk_results);
	if (!upds)
	{
		reason = "Failed to get packages update detail";
		goto fail;
	}

	g_assert_true(upds->len == pkgs->len);

	g_ptr_array_sort(upds, upd_cmp_by_pkg_id);

	pkg_ids = g_ptr_array_sized_new(total_upd_count + 1);

	for (size_t i = 0; i < upds->len; i++)
	{
		PkUpdateDetail *upd = (PkUpdateDetail *)g_ptr_array_index(upds, i);
		const gchar *pkg_id = pk_update_detail_get_package_id(upd);
		gchar **cve_urls = pk_update_detail_get_cve_urls(upd);
		const gchar *changelog = pk_update_detail_get_changelog(upd);
		PkPackage *pkg = (PkPackage *)g_ptr_array_index(pkgs, i);
		PkInfoEnum pkg_info = pk_package_get_info(pkg);
		int add_pkg = 0;
		long int dummy;

		g_assert_cmpstr(pkg_id, ==, pk_package_get_id(pkg));

		if (must_upd_pkg)
			add_pkg = 1;

		if (cve_urls && cve_urls[0]
				|| (changelog && strstr(changelog, "CVE-"))
				|| pkg_info & PK_INFO_ENUM_SECURITY)
		{
			sec_upd_count++;

			if (must_upd_sec_pkg)
				add_pkg = 1;

			gchar *pkg_name = pk_package_id_to_printable(pkg_id);
			printf("%s\n", pkg_name);
			g_free(pkg_name);
		}

		if (add_pkg)
			g_ptr_array_add(pkg_ids, (gchar *)pkg_id);
	}

	g_object_unref(pkgs);

	if (must_upd_pkg || must_upd_sec_pkg)
	{
		g_ptr_array_add(pkg_ids, NULL);

		pk_results = pk_client_update_packages(cli, PK_TRANSACTION_FLAG_ENUM_NONE, (gchar **)pkg_ids->pdata, NULL, pk_progress_cb, NULL, &gerror);
		g_ptr_array_unref(pkg_ids);
		g_ptr_array_unref(upds);
		if (!pk_results)
		{
			reason = "Failed to update packages";
			goto fail;
		}
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

	printf("UPDATE %s - Security-Update = %zu | 'Total Update' = %zu\n", panic_str, sec_upd_count, total_upd_count);

	result = 0;
	status = 0;

fail:
	g_object_unref(cli);

fail_new_cli:
	if (result < 0)
	{
		const char *gerror_msg = (gerror && gerror->message) ? gerror->message : "";

		status = 2;
		printf("UPDATE Critical | An error occurred: %s%s%s\n", reason, gerror_msg[0] ? ": " : "", gerror_msg);
	}

	if (gerror)
		g_error_free(gerror);

	return status;
}
