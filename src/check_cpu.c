#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

struct cpu_stats
{
	uint64_t user, nice, system, idle;
};

static unsigned int get_core_count(void)
{
	FILE *fp;
	char line[1024];
	unsigned int tmp, count;

	count = 0;

	fp = fopen("/proc/stat", "r");

	while (!feof(fp) && !ferror(fp))
	{
		if (!fgets(line, sizeof(line), fp))
			continue;

		if (strncmp(&line[0], "cpu", 3) != 0)
			continue;

		if (!isdigit(line[3]))
			continue;

		tmp = strtoul(&line[3], NULL, 10);
		if (tmp > count)
			count = tmp;
	}

	fclose(fp);

	return count + 1;
}

static void dump_cpu(struct cpu_stats *cpu, const char *s)
{
	sscanf(s, "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
			&cpu->user, &cpu->nice, &cpu->system, &cpu->idle);
}

static void dump_cores(struct cpu_stats *cpu, unsigned int count, struct cpu_stats *cores)
{
	FILE *fp;
	char line[1024];
	unsigned int i;
	char *nptr;

	fp = fopen("/proc/stat", "r");

	while (!feof(fp) && !ferror(fp))
	{
		if (!fgets(line, sizeof(line), fp))
			continue;

		if (strncmp(&line[0], "cpu", 3) != 0)
			continue;

		if (isspace(line[3]))
		{
			dump_cpu(cpu, &line[4]);
			continue;
		}

		if (!isdigit(line[3]))
			continue;

		i = strtoul(&line[3], &nptr, 10);
		if (i >= count)
			continue;

		dump_cpu(&cores[i], nptr);
	}

	fclose(fp);
}

static float get_cpu_pct(struct cpu_stats *cpu0, struct cpu_stats *cpu1)
{
	uint64_t used_total0 = cpu0->user + cpu0->nice + cpu0->system;
	uint64_t used_total1 = cpu1->user + cpu1->nice + cpu1->system;
	uint64_t total0 = used_total0 + cpu0->idle;
	uint64_t total1 = used_total1 + cpu1->idle;

	return (used_total1 - used_total0) * 10000 / (total1 - total0) / 100.f;
}

int main(int argc, char **argv)
{
	int result;
	FILE *fp;
	float warn_threshold;
	float crit_threshold;
	unsigned int core_count;
	struct cpu_stats cpu0, cpu1;
	struct cpu_stats *cores0, *cores1;
	float cpu_pct;
	const char *panic_str;

	/* cmd line : $0 -w warn_threshold -c crit_threshold */
	warn_threshold = strtof(argv[2], NULL);
	crit_threshold = strtof(argv[4], NULL);

	core_count = get_core_count();
	if (core_count)
	{
		cores0 = calloc(core_count, sizeof(cores0[0]));
		cores1 = calloc(core_count, sizeof(cores1[0]));
	}

	dump_cores(&cpu0, core_count, cores0);

	sleep(1);

	dump_cores(&cpu1, core_count, cores1);

	cpu_pct = get_cpu_pct(&cpu0, &cpu1);

	panic_str = "OK";
	result = 0;
	if (cpu_pct > crit_threshold)
	{
		panic_str = "Critical";
		result = 2;
	}
	else if (cpu_pct > warn_threshold)
	{
		panic_str = "Warning";
		result = 1;
	}

	printf("%s: CPU Used = %.2f%% | ", panic_str, cpu_pct);

	for (unsigned int i = 0; i < core_count; i++)
		printf("Core %u = %.2f%%%s", i, get_cpu_pct(&cores0[i], &cores1[i]), (i < core_count - 1) ? "; " : "\n");

	if (core_count)
	{
		free(cores0);
		free(cores1);
	}

	return result;
}
