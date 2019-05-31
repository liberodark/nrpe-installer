#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#define INVAL_SIZE UINT64_C(0xFFFFFFFFFFFFFFFF)

struct mem_stats
{
	uint64_t total_kB;
	uint64_t avail_kB;
	uint64_t free_kB;
	uint64_t buffers_kB;
	uint64_t cached_kB;
	uint64_t used_kB;
};

static void dump_mem_stats(struct mem_stats *mem_stats)
{
	FILE *fp;
	char line[1024];
	unsigned int i;
	char *nptr;

	fp = fopen("/proc/meminfo", "r");

	mem_stats->total_kB = INVAL_SIZE;
	mem_stats->avail_kB = INVAL_SIZE;
	mem_stats->free_kB = INVAL_SIZE;
	mem_stats->buffers_kB = INVAL_SIZE;
	mem_stats->cached_kB = INVAL_SIZE;
	mem_stats->used_kB = INVAL_SIZE;

	while (!feof(fp) && !ferror(fp))
	{
		if (!fgets(line, sizeof(line), fp))
			continue;

		if (strncmp(&line[0], "MemTotal:", 9) == 0)
		{
			mem_stats->total_kB = strtoull(&line[9], &nptr, 10);
			continue;
		}

		if (strncmp(&line[0], "MemAvailable:", 13) == 0)
		{
			mem_stats->avail_kB = strtoull(&line[13], &nptr, 10);
			continue;
		}

		if (strncmp(&line[0], "memFree:", 8) == 0)
		{
			mem_stats->free_kB = strtoull(&line[8], &nptr, 10);
			continue;
		}

		if (strncmp(&line[0], "Buffers:", 8) == 0)
		{
			mem_stats->buffers_kB = strtoull(&line[8], &nptr, 10);
			continue;
		}

		if (strncmp(&line[0], "Cached:", 7) == 0)
		{
			mem_stats->cached_kB = strtoull(&line[7], &nptr, 10);
			continue;
		}
	}

	fclose(fp);

	if (mem_stats->avail_kB == INVAL_SIZE)
	{
		mem_stats->avail_kB = 0;

		if (mem_stats->free_kB != INVAL_SIZE)
			mem_stats->avail_kB += mem_stats->free_kB;

		if (mem_stats->buffers_kB != INVAL_SIZE)
			mem_stats->avail_kB += mem_stats->buffers_kB;

		if (mem_stats->cached_kB != INVAL_SIZE)
			mem_stats->avail_kB += mem_stats->cached_kB;
	}

	if (mem_stats->used_kB == INVAL_SIZE)
		mem_stats->used_kB = mem_stats->total_kB - mem_stats->avail_kB;
}

int main(int argc, char **argv)
{
	int result;
	float warn_threshold;
	float crit_threshold;
	struct mem_stats stats;
	float mem_pct;
	const char *panic_str;

	/* cmd line : $0 -w warn_threshold -c crit_threshold */
	warn_threshold = strtof(argv[2], NULL);
	crit_threshold = strtof(argv[4], NULL);

	dump_mem_stats(&stats);

	mem_pct = 10000 * stats.used_kB / stats.total_kB / 100.f;

	panic_str = "OK";
	result = 0;
	if (mem_pct >= crit_threshold)
	{
		panic_str = "Critical";
		result = 2;
	}
	else if (mem_pct >= warn_threshold)
	{
		panic_str = "Warning";
		result = 1;
	}

	printf("MEMORY %s - Used = %.2f%% | Total: %" PRIu64 " MB Used: %" PRIu64 " MB Free: %" PRIu64 " MB\n", panic_str, mem_pct, stats.total_kB / 1024, stats.used_kB / 1024, stats.avail_kB / 1024);

	return result;
}
