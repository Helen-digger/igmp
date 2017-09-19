#ifndef _IGMP_TIMERS_
#define _IGMP_TIMERS_

#define _POSIX_C_SOURCE 199309L

#include "protocol.h"

typedef struct timers {
	uint32_t        group;
	struct timespec timer;
} timers;

#define GROUP_COUNT 128

inline static struct timespec sum_time(struct timespec l, struct timespec r)
{
	struct timespec res = {0, 0};
	res.tv_sec = l.tv_sec + r.tv_sec + (l.tv_nsec + r.tv_nsec)/1000000000L;
	res.tv_nsec = (l.tv_nsec + r.tv_nsec)%1000000000L;
	return res;
}

inline static struct timespec sub_time(struct timespec l, struct timespec r)
{
	struct timespec res = {0, 0};
	res.tv_sec = l.tv_sec - r.tv_sec - ((l.tv_nsec - r.tv_nsec) < 0L ? 1 : 0);
	res.tv_nsec = (l.tv_nsec - r.tv_nsec)%1000000000L < 0 ? 1000000000L + (l.tv_nsec - r.tv_nsec) : (l.tv_nsec - r.tv_nsec);
	return res;
}

inline static int cmp_time(struct timespec l,struct timespec r)
{
	if (l.tv_sec >  r.tv_sec) return  1;
	if (l.tv_sec <  r.tv_sec) return -1;
	if (l.tv_sec == r.tv_sec)
	{
		if (l.tv_nsec > r.tv_nsec) return  1;
		if (l.tv_nsec < r.tv_nsec) return -1;
	}
	return 0;
}

inline static struct timespec igmp_code_to_time(uint8_t c)
{
	struct timespec res = {0, 0};
	res.tv_sec = c/10;
	res.tv_nsec = c%10*100000000L;
	return res;
}

inline static long long time_to_ll(struct timespec t)
{
	return 1000000000L*t.tv_sec+t.tv_nsec;
}

inline static int ms_left(struct timespec l, struct timespec r)
{
	return (time_to_ll(sub_time(l,r)) / 1000000);
}

inline static struct timespec ll_to_time(long long l)
{
	struct timespec res = {0, 0};
	res.tv_sec  = l / 1000000000L;
	res.tv_nsec = l % 1000000000L;
	return res;
}

inline static int timer_is_set(struct timespec t)
{
	return (t.tv_sec != 0 || t.tv_nsec != 0);
}

inline static void drop_timer(struct timespec * t)
{
	t->tv_sec = 0;
	t->tv_nsec = 0;
	return;
}

inline static int is_time_to_send(struct timespec now, struct timespec timer)
{
	return (0 <= cmp_time(now, timer) && timer_is_set(timer));
}

inline static int need_to_reset_timer(struct timespec end, struct timespec timer)
{
	return (0 <= cmp_time(end, timer) || !timer_is_set(timer));
}

inline static struct timespec when_time_expires(uint8_t code)
{
	struct timespec tp = {0, 0};
	clock_gettime(CLOCK_REALTIME, &tp);
	return sum_time(tp, igmp_code_to_time(code));
}

inline static struct timespec gen_timer(struct timespec end, struct timespec start)
{
	long long val = time_to_ll(sub_time(end,start))%25500000001L, new = 0;
	new = rand();
	new = ((new << 32) + rand())%val;
	return sum_time(start, ll_to_time(new));
}

int show_timers(struct timers * timers);

int show_groups(struct timers * timers);

int search_group(struct timers * timers, uint32_t gr);

int add_group(struct timers * timers, uint32_t gr);

int del_group(struct timers * timers, uint32_t gr);

int refresh_timers(struct timers * timers, uint32_t gr, uint8_t code);

#endif /*_IGMP_TIMERS_*/
