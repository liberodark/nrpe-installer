#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmodule.h>

#define I_KNOW_THE_PACKAGEKIT_GLIB2_API_IS_SUBJECT_TO_CHANGE 1

#include <packagekit-glib2/packagekit.h>


enum opt_id
{
	OPT_C = 0,
	OPT_SECURITY_UPDATE,
	OPT_UPDATE,
	OPT_W,
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
	fprintf(stderr, "Usage: %s -w <warn_treshold> -c <crit_treshold> [-security-update] [-update]\n", (argc >= 1) ? argv[0] : "check_pkg");
	return 1;
}

int main(int argc, char **argv)
{
#define OPT_NONE(e, n) [e] = { .type = OPT_TYPE_NONE, .name = n }
#define OPT_STR(e, n) [e] = { .type = OPT_TYPE_STR, .name = n }
#define OPT_INT(e, n) [e] = { .type = OPT_TYPE_INT, .name = n }
#define OPT_END() [OPT_COUNT] = { .type = OPT_TYPE_INVAL, .name = NULL }
	struct opt opt_tpl[] = {
		OPT_INT(OPT_C, "-c"),
		OPT_INT(OPT_W, "-w"),
		OPT_NONE(OPT_SECURITY_UPDATE, "-security-update"),
		OPT_NONE(OPT_UPDATE, "-update"),
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
	int must_upd_pkg = 0;
	int must_upd_sec_pkg = 0;
	PkClient *cli;
	GError *gerror = NULL;
	PkResults *pk_results;
	GPtrArray *pkgs;
	GPtrArray *upd_pkg_ids;
	size_t total_upd_count = 0;
	size_t sec_upd_count = 0;
	const char *panic_str;

	opts = parse_opts(argc, argv, opt_tpl);
	if (!opts)
		return print_usage(argc, argv);

	if (!get_opt_defined(opts, OPT_C) || !get_opt_defined(opts, OPT_W))
		return print_usage(argc, argv);

	must_upd_pkg = get_opt_defined(opts, OPT_UPDATE);
	must_upd_sec_pkg = get_opt_defined(opts, OPT_SECURITY_UPDATE);

	cli = pk_client_new();
	if (!cli)
	{
		reason = "Failed to create a new PackageKit client";
		goto fail_new_cli;
	}

	pk_results = pk_client_get_updates(cli, PK_FILTER_ENUM_NONE, NULL, NULL, NULL, &gerror);
	if (!pk_results)
	{
		reason = "Failed to get the list of updates";
		goto fail;
	}

	pkgs = pk_results_get_package_array(pk_results);
	g_object_unref(pk_results);
	if (!pkgs)
	{
		reason = "Failed to get packages from the list of updates";
		goto fail;
	}

	total_upd_count = pkgs->len;

	if (must_upd_pkg || must_upd_sec_pkg)
	{
		/* Keep a ref for pkg ids */
		g_ptr_array_ref(pkgs);
		upd_pkg_ids = g_ptr_array_sized_new(total_upd_count + 1);
	}

	for (size_t i = 0; i < pkgs->len; i++)
	{
		PkPackage *pkg = (PkPackage *)g_ptr_array_index(pkgs, i);
		PkInfoEnum pkg_info;
		int add_pkg = 0;

		if (must_upd_pkg)
			add_pkg = 1;

		pkg_info = pk_package_get_info(pkg);
		if (pkg_info & PK_INFO_ENUM_SECURITY)
		{
			sec_upd_count++;
			if (must_upd_sec_pkg)
				add_pkg = 1;
		}

		if (add_pkg)
			g_ptr_array_add(upd_pkg_ids, (void *)pk_package_get_id(pkg));
	}

	g_ptr_array_unref(pkgs);

	if (must_upd_pkg || must_upd_sec_pkg)
	{
		g_ptr_array_add(upd_pkg_ids, NULL);

		pk_results = pk_client_update_packages(cli, 0, (gchar **)upd_pkg_ids->pdata, NULL, NULL, NULL, &gerror);
		g_ptr_array_unref(upd_pkg_ids);
		g_ptr_array_unref(pkgs);
		if (!pk_results)
		{
			reason = "Failed to update packages";
			goto fail;
		}
	}

	panic_str = "OK";
	status = 0;
	if (sec_upd_count >= get_opt_int(opts, OPT_C))
	{
		panic_str = "Critical";
		status = 2;
	}
	else if (sec_upd_count >= get_opt_int(opts, OPT_W))
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
