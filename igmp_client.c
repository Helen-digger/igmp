/*IGMP client

	Написать консольное приложение, которое будет эмулировать IGMP-клиента:
	 запрашивать список мультикаст-групп
	 и прекращать подписку на них.

	Параметрами командной строки утилите передается диапазон IP-адресов групп 
	и имя интерфейса (ethN), через который отправлять сообщения (парсинг опций через getopt).

	 При запуске утилита посылает IGMP report на все указанные в командной строке группы и переходит в режим ожидания.

	 Утилита (клиент) должна отвечать IGMP-репортами на входящие с ethN сообщения IGMP general query и IGMP group specific query (если GSQ пришла на одну из наших групп).

	Ответ должен быть реализован с задержкой согласно RFC-2236.

	Также в режиме ожидания должна быть реализована возможность корректировки списка прослушиваемых групп с клавиатуры:
	 команда "add <IP>" добавляет группу к списку с полследующей отправкой Report,
	 команда "del <IP>" удаляет группу из списка с последующей отправкой Leave.

	 К тестовому заданию приложить скрипты для генератора трафика с пакетами IGMP.

	Реализовать на чистом Си. Сборка должна проходить с флагом -Werror без ошибок. Сообщить срок реализации в часах.
*/

extern int usleep (unsigned long long __useconds);

#include "protocol.h"
#include <pthread.h>

typedef struct ARGS_DATA{
	struct timers    * timers;
	char             * ifname;
	pthread_mutex_t  * l;
} ARGS_DATA;

typedef struct timers {
	uint32_t        group;
	struct timespec timer;
} timers;

#define CMD_LEN 64
#define ARG_LEN 16
#define LISTENING_SOCKET 1000
#define CHECK_TIMERS_INT 10000
#define IDLE_TIMERS_INT 1000000

#define USAGE(_name_) fprintf(stderr, "Usage: %s -i <IFNAME> -b <start-IP> [-e <end-IP>]\n", _name_)
#define CLI_ADD   "\tadd\t<IP> - add group\n"
#define CLI_DEL   "\tdel\t<IP> - delete group\n"
#define CLI_GROUP "\tgroups\tshow added groups\n"
#define CLI_TIMER "\ttimers\tshow active timers value\n"
#define CLI_EXIT  "\texit\tstop client and quit\n"
#define CLI_USAGE(_cmd_) fprintf(stderr, "invalid cmd:'%s'\nUsage:\n%s%s%s%s%s", \
                                 _cmd_, CLI_ADD, CLI_DEL, CLI_GROUP, CLI_TIMER, CLI_EXIT);

#define TSSUM(l,r) (struct timespec){l.tv_sec + r.tv_sec + (l.tv_nsec + r.tv_nsec)/1000000000L, (l.tv_nsec + r.tv_nsec)%1000000000L}
#define TSSUB(l,r) (struct timespec){l.tv_sec - r.tv_sec - ((l.tv_nsec - r.tv_nsec) < 0L ? 1 : 0), \
 (l.tv_nsec - r.tv_nsec)%1000000000L < 0 ? 1000000000L + (l.tv_nsec - r.tv_nsec) : (l.tv_nsec - r.tv_nsec)}
#define CODE2TS(c) (struct timespec){c/10, c%10*100000000L}
#define TS2L(t) (long long)(1000000000L*t.tv_sec+t.tv_nsec)
#define L2TS(l) (struct timespec){.tv_sec = l/1000000000L, .tv_nsec = l%1000000000L}
#define LAST(l,r) (int)(TS2L(TSSUB(l,r))/1000000)
#define ISSET(t) (int)(t.tv_sec != 0 || t.tv_nsec != 0)
#define DROP(t) {t.tv_sec = 0; t.tv_nsec = 0;}
#define NEEDSEND(now,timer) (int)(0 <= TSCMP(now, timer) && ISSET(timer))
#define NEEDRESET(end,timer) (int)(0 <= TSCMP(end, timer) || !ISSET(timer))

extern char * optarg;
extern int optin;
extern int opterr;
extern int optopt;

int group_count = 0;
pthread_mutex_t lock;

inline static int TSCMP(struct timespec l,struct timespec r)
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

inline static struct timespec NOW_PLUS_CODE(uint8_t code)
{
	struct timespec tp = {0, 0};
	clock_gettime(CLOCK_REALTIME, &tp);
	return TSSUM(tp, CODE2TS(code));
}

inline static struct timespec RND_TIMER1(struct timespec end, struct timespec start)
{
	long long val = TS2L(TSSUB(end,start))%25500000001L, new = 0;
	new = rand();
	new = ((new << 32) + rand())%val;
	return TSSUM(start, L2TS(new));
}

int show_timers(struct timers * timers)
{
	int printed = 0;
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if(timers[i].group == 0) continue;
		if(ISSET(timers[i].timer) == 0) continue;
		printed++;
		if(1 == printed) printf("GPOUP\t\tLEFT(ms)\n");
		printf("%s\t%d\n",
		        inet_ntoa((struct in_addr){timers[i].group}),
		        LAST(timers[i].timer,now));
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
			timers[i].timer = RND_TIMER1(NOW_PLUS_CODE(MIN_IMGP_CODE), now);
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
			DROP(timers[i].timer);
			group_count--;
			return 1;
		}
	return 0;
}

int refresh_timers(struct timers * timers, uint32_t gr, uint8_t code)
{
	struct timespec now = {0,0}, end = NOW_PLUS_CODE(code != 0 ? code : IGMP_GQUERY_CODE);
	clock_gettime(CLOCK_REALTIME, &now);
	if (gr)
	{
		int idx = search_group(timers, gr);
		if (idx == -1) return -1;
		if (NEEDRESET(end, timers[idx].timer))
		{
			timers[idx].timer = RND_TIMER1(end, now);
		}
		return 0;
	}
	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if (timers[i].group)
			if (NEEDRESET(end, timers[i].timer))
			{
				timers[i].timer = RND_TIMER1(end, now);
			}
	}
	return 0;
}

int fill_groups(struct timers * timers, char * ipstr, char * ipend, unsigned char eflag)
{
	uint32_t b_ip = ntohl(inet_addr(ipstr));
	uint32_t e_ip = eflag ? ntohl(inet_addr(ipend)) : b_ip;
	struct timespec now = {0,0}, end = NOW_PLUS_CODE(IGMP_GQUERY_CODE);
	clock_gettime(CLOCK_REALTIME, &now);

	if (e_ip < b_ip || GROUP_COUNT < (e_ip - b_ip))
	{
		fprintf(stderr,"'%s': wrong ip range is set! it should be less %d\n", __func__, GROUP_COUNT);
		return -1;
	}

	for(uint32_t i = 0; i <= (e_ip - b_ip); i++)
	{
		timers[i].group = htonl(b_ip + i);
		timers[i].timer = RND_TIMER1(end, now);
		group_count++;
	}
	return 0;
}

void * handle_queries(void * arg)
{
	struct timers   * timers = ((ARGS_DATA *)arg)->timers;
	char            * ifname = ((ARGS_DATA *)arg)->ifname;
	pthread_mutex_t * l      = ((ARGS_DATA *)arg)->l;

	int sd = 0;
	igmp_pack p;
	INIT_SOCK(sd, ifname);
	struct timespec now;
	do {
		clock_gettime(CLOCK_REALTIME, &now);
		pthread_mutex_lock(l);
		for(int i = 0; i < GROUP_COUNT; i++)
		{
			if (timers[i].group && ISSET(timers[i].timer))
				if (NEEDSEND(now, timers[i].timer))
				{
					BLD_REPORT(p, ifname, timers[i].group);
					SEND_PACK(sd, p);
					DROP(timers[i].timer);
				}
		}
		pthread_mutex_unlock(l);
		if (group_count > 0) 
		{
			usleep(CHECK_TIMERS_INT);
			continue;
		}
		if (group_count == 0) usleep(IDLE_TIMERS_INT);
		if (group_count < 0)
		{
			close(sd);
			pthread_exit(NULL);
		}
	} while (1);
}

int send_leave(char * ifname, uint32_t gr)
{
	int sd = 0;
	igmp_pack p;
	INIT_SOCK(sd, ifname);
	BLD_LEAVE(p, ifname, gr);
	SEND_PACK(sd, p);
	close(sd);
	return 0;
}

int listen_igmp(struct timers * timers, char * ifname, pthread_mutex_t * l)
{
	int sd = 0, error = 0, timeOut = 0, search = 0;
	uint8_t buffer[BUFF_SIZE] = {0};
	igmp_pack * p = (igmp_pack *)(buffer + sizeof(struct ether_header));

	INIT_FILTERING_SOCK(sd, ifname);

	ssize_t rcv;
	struct igmp * pl;
	do {
		rcv = 0;
		search = -1;
		memset(buffer, 0, BUFF_SIZE);
		timeOut = LISTENING_SOCKET;
		if (isReadable(sd, &error, timeOut)) 
		{
			if (0 >( rcv = recv(sd, buffer, sizeof(buffer), 0)))
			{
				fprintf(stderr,"%s recvfrom failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
				return -1;
			}
		}
		pl =(struct igmp *)(buffer + sizeof(struct ether_header) + 4*p->ph.ihl);

		if (pl->igmp_type == IGMP_MEMBERSHIP_QUERY)
		{
			pthread_mutex_lock(l);
			refresh_timers(timers, pl->igmp_group.s_addr, pl->igmp_code);//
			pthread_mutex_unlock(l);
		}
		if (pl->igmp_type == IGMP_V2_MEMBERSHIP_REPORT)
		{
			pthread_mutex_lock(l);
			search = search_group(timers, pl->igmp_group.s_addr);
			if (-1 != search) DROP(timers[search].timer);
			pthread_mutex_unlock(l);
		}
	} while(group_count > 0);

	close(sd);
	return 0;
}

void * cli(void *arg)
{
	struct timers   * timers = ((ARGS_DATA *)arg)->timers;
	char            * ifname = ((ARGS_DATA *)arg)->ifname;
	pthread_mutex_t * l      = ((ARGS_DATA *)arg)->l;
	int status = 1;
	char command[CMD_LEN];
	char argument[ARG_LEN];
	do {
		memset(command, 0, CMD_LEN);
		memset(argument, 0, ARG_LEN);
		printf("> ");
		//fflush(stdin);
		if (0 == scanf ("\n%[^\n]s", command)) command[0] = '\n';

		if (1 == sscanf(command, "add %s", argument))
		{
			if (0 != check_ip(argument)) continue;
			pthread_mutex_lock(l);
			if (-1 != search_group(timers, inet_addr(argument)))
			{
				printf("group %s already added\n", argument);
			}
			else if (!add_group(timers, inet_addr(argument)))
			{
				printf("add failed, del some group first\n");
			}
			pthread_mutex_unlock(l);
		}

		else if (1 == sscanf(command, "del %s", argument))
		{
			if (0 != check_ip(argument)) continue;
			pthread_mutex_lock(l);
			if (del_group(timers, inet_addr(argument)))
			{
				printf("group %s deleted\n", argument);
				send_leave(ifname, inet_addr(argument));
			}
			else printf("group %s not found\n", argument);
			pthread_mutex_unlock(l);
		}

		else if (0 == strncmp(command, "groups", CMD_LEN))
		{
			pthread_mutex_lock(l);
			show_groups(timers);
			pthread_mutex_unlock(l);
		}

		else if (0 == strncmp(command, "timers", CMD_LEN))
		{
			pthread_mutex_lock(l);
			show_timers(timers);
			pthread_mutex_unlock(l);
		}

		else if (0 == strncmp(command, "exit", CMD_LEN))
		{
			pthread_mutex_lock(l);
			status = 0;
			group_count = -1;
			pthread_mutex_unlock(l);
		}

		else if (command[0] == '\n') 
		{
			printf("%s", command);
			fflush(stdin);
			continue;
		}
		else CLI_USAGE(command);
	} while (status);

	pthread_exit(NULL);
}

int main (int argc, char **argv)
{
	srand(time(NULL));

	unsigned char iflag = 0;
	unsigned char bflag = 0;
	unsigned char eflag = 0;
	char *ipstr = NULL;
	char *ipend = NULL;
	char *ifname = NULL;
	int c;

	while (-1 != (c = getopt (argc, argv, "i:b:e:?")))
		switch (c)
		{
			case 'i':
				iflag = 1;
				ifname = optarg;
				break;
			case 'b':
				bflag = 1;
				ipstr = optarg;
				if (0 != check_ip(ipstr)) return -1;
				break;
			case 'e':
				eflag = 1;
				ipend = optarg;
				if (0 != check_ip(ipend)) return -1;
				break;
			case '?':
				if      (optopt == 'i')    fprintf (stderr, "Option -%c requires <IFNAME> argument.\n", optopt);
				else if (optopt == 'b')    fprintf (stderr, "Option -%c requires <IP> argument.\n", optopt);
				else if (optopt == 'e')    fprintf (stderr, "Option -%c requires <IP> argument.\n", optopt);
				else if (isprint (optopt)) fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else                       fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return -1;
			default:
				abort();
		}

	if (iflag == 0)
	{
		USAGE(argv[0]);
		return -1;
	}

	struct timers * timers = (struct timers *)malloc(GROUP_COUNT * sizeof(struct timers));
	memset(timers, 0, GROUP_COUNT * sizeof(struct timers));

	pthread_t tcli, thq;
	pthread_mutex_init(&lock, NULL);

	ARGS_DATA cli_data = {timers, ifname, &lock};
	ARGS_DATA hq_data  = {timers, ifname, &lock};

	if (bflag)
	{
		if(0 != fill_groups(timers, ipstr, ipend, eflag)) return -1;
		if(0 != pthread_create(&thq, NULL, handle_queries, (void *)&hq_data))
		{
			fprintf(stderr,"%spthread_create failed:%s\n", argv[0], (errno ? strerror(errno) : "ok"));
			return -1;
		}
	}


	if(0 != pthread_create(&tcli, NULL, cli, (void *)&cli_data))
	{
		fprintf(stderr,"%spthread_create failed:%s\n", argv[0], (errno ? strerror(errno) : "ok"));
		return -1;
	}

	listen_igmp(timers, ifname, &lock);

	pthread_join(thq, NULL);
	pthread_join(tcli, NULL);

	free(timers);
	pthread_mutex_destroy(&lock);

	return 0;
}
