#include "timers.h"

int group_count = 0;

int show_timers(struct timers * timers)
{
	int printed = 0;
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if(timers[i].group == 0) continue;
		if(timer_is_set(timers[i].timer) == 0) continue;
		printed++;
		if(1 == printed) printf("GPOUP\t\tLEFT(ms)\n");
		printf("%s\t%d\n",
		        inet_ntoa((struct in_addr){timers[i].group}),
		        ms_left(timers[i].timer,now));
	}
	printf("%d timers active\n",printed);
	return printed;
}

int show_groups(struct timers * timers)
{
	int printed = 0;
	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if(timers[i].group == 0) continue;
		
		printf("%s\n", inet_ntoa((struct in_addr){timers[i].group}));
		printed++;
	}
	printf("subscribed to %d groups\n",printed);
	return printed;
}

int search_group(struct timers * timers, uint32_t gr)
{
	for(int i = 0; i < GROUP_COUNT; i++)
		if (timers[i].group == gr) return i;
	return -1;
}

int add_group(struct timers * timers, uint32_t gr)
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if (timers[i].group == 0)
		{
			timers[i].group = gr;
			timers[i].timer = gen_timer(when_time_expires(IGMP_SQUERY_CODE), now);
			group_count++;
			return 1;
		}
	}
	return 0;
}

int del_group(struct timers * timers, uint32_t gr)
{
	for(int i = 0; i < GROUP_COUNT; i++)
		if (timers[i].group == gr) 
		{
			timers[i].group = 0;
			drop_timer(&timers[i].timer);
			group_count--;
			return 1;
		}
	return 0;
}

int refresh_timers(struct timers * timers, uint32_t gr, uint8_t code)
{
	struct timespec now = {0,0}, end = when_time_expires(code != 0 ? code : IGMP_GQUERY_CODE);
	clock_gettime(CLOCK_REALTIME, &now);
	if (gr)
	{
		int idx = search_group(timers, gr);
		if (idx == -1) return -1;
		if (need_to_reset_timer(end, timers[idx].timer))
		{
			timers[idx].timer = gen_timer(end, now);
		}
		return 0;
	}

	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if (timers[i].group)
			if (need_to_reset_timer(end, timers[i].timer))
			{
				timers[i].timer = gen_timer(end, now);
			}
	}

	return 0;
}
