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

//extern int usleep (unsigned long long __useconds);

#include "protocol.h"
#include <pthread.h>

#define CMD_LEN 64
#define ARG_LEN 16

#define USAGE(_name_) fprintf(stderr, "Usage: %s -i <IFNAME> -b <IP> [-e <IP>]\n", _name_)
#define CLI_USAGE(_cmd_) fprintf(stderr, "invalid cmd:'%s'\nUsage:\n\tadd\t<IP> - add group\n\tdel\t<IP> - delete group\n", _cmd_)

typedef struct CLI_DATA{
	uint32_t        * groups;
	char            * ifname;
	pthread_mutex_t * l;
} CLI_DATA;
typedef struct HGQ_DATA{
	uint32_t         * groups;
	struct timeval   * timers;
	char             * ifname;
	struct igmp_pack * rp;
	time_t             start;
} HGQ_DATA;

extern char * optarg;
extern int optin;
extern int opterr;
extern int optopt;

int group_count = 0;

int search_group(uint32_t * groups, uint32_t gr)
{
	for(int i = 0; i < GROUP_COUNT; i++)
		if (groups[i] == gr) return i;
	return -1;
}

int add_group(uint32_t * groups, uint32_t gr)
{
	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if (groups[i] == 0)
		{
			groups[i] = gr;
			group_count++;
			return 1;
		}
	}
	return 0;
}

int del_group(uint32_t * groups, uint32_t gr)
{
	for(int i = 0; i < GROUP_COUNT; i++)
		if (groups[i] == gr) 
		{
			groups[i] = 0;
			group_count--;
			return 1;
		}
	return 0;
}

int fill_groups(uint32_t * groups, char * ipstr, char * ipend, unsigned char eflag)
{
	uint32_t b_ip = ntohl(inet_addr(ipstr));
	uint32_t e_ip = eflag ? ntohl(inet_addr(ipend)) : b_ip;

	if (e_ip < b_ip || GROUP_COUNT < (e_ip - b_ip))
	{
		fprintf(stderr,"'%s': wrong ip range is set! it should be less %d\n", __func__, GROUP_COUNT);
		return -1;
	}

	for(uint32_t i = 0; i <= (e_ip - b_ip) && i < GROUP_COUNT; i++)
	{
		groups[i] = htonl(b_ip + i);
		group_count++;
	}

	return 0;
}

int refresh_timers(struct timeval * timers, uint32_t * groups)
{
	struct timeval now;
	gettimeofday(&now, NULL);

	for(uint32_t i = 0; i < GROUP_COUNT; i++)
	{
		if (groups[i])
		timers[i] = (struct timeval){now.tv_sec + rand()%9,now.tv_usec + rand()%900000};
	}
	return 0;
}

void * handle_general_query(void * arg)
{
	uint32_t         * groups = ((HGQ_DATA *)arg)->groups;
	struct timeval   * timers = ((HGQ_DATA *)arg)->timers;
	char             * ifname = ((HGQ_DATA *)arg)->ifname;
	//struct igmp_pack * rp     = ((HGQ_DATA *)arg)->rp;
	//time_t             start  = ((HGQ_DATA *)arg)->start;
	int sd = 0;
	igmp_pack p;
	INIT_SOCK(sd, ifname);
	struct timeval now;
	int rem = group_count;
	do {
		for(uint32_t i = 0; i < GROUP_COUNT; i++)
		{
			if (groups[i] == 0 || timers[i].tv_sec == 0) continue;
			gettimeofday(&now, NULL);
			if (now.tv_sec > timers[i].tv_sec ||
				(now.tv_sec == timers[i].tv_sec && now.tv_usec >= timers[i].tv_usec))
			{
				BLD_REPORT(p, ifname, groups[i]);
				SEND_PACK(sd, p);
				timers[i] = (struct timeval){0,0};
				rem--;
			}
		}
	} while (rem);
	close(sd);

	pthread_exit(NULL);
}

int send_report(uint32_t * groups, char * ifname, uint32_t target)
{
	int sd = 0;
	igmp_pack p;
	INIT_SOCK(sd, ifname);
	BLD_REPORT(p, ifname, target);
	SEND_PACK(sd, p);
	close(sd);
	return 0;
}

int send_leave(uint32_t * groups, char * ifname, uint32_t target)
{
	int sd = 0;
	igmp_pack p;
	INIT_SOCK(sd, ifname);
	BLD_LEAVE(p, ifname, target);
	SEND_PACK(sd, p);
	close(sd);
	return 0;
}

int listen_queries(uint32_t * groups, char * ifname)
{
	//time_t start = 0;
	int sd = 0;
	igmp_frame p;
	if (0 > (sd = socket(PF_INET, SOCK_DGRAM, 0)))
	{
		fprintf(stderr,"%s socket failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
		return -1;
	}
	ssize_t rcv;
	for(;;)
	{
		do {
			rcv = 0;
			memset(&p, 0, sizeof(struct igmp_frame));
			if (0 >( rcv = recv(sd, &p, sizeof(p), 0)))
			{
				fprintf(stderr,"%s recvfrom failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
				return -1;
			}
			if (p.pl.type == IGMP_HOST_MEMBERSHIP_QUERY && p.frame_hdr.h_proto == htons(ETH_P_IP)) break;
				printf("recieved %lu , %lu\n", rcv, sizeof(p));

				/*PRINT_MAC("shw:\t%02x:%02x:%02x:%02x:%02x:%02x\n",p.frame_hdr.h_source);
				PRINT_MAC("dhw:\t%02x:%02x:%02x:%02x:%02x:%02x\n",p.frame_hdr.h_dest);
				printf("proto:\t%x\n", ntohs(p.frame_hdr.h_proto));*/

				printf("ihl:\t%x\n", p.ip_hdr.ihl);
				printf("ver:\t%x\n", p.ip_hdr.version);
				printf("tos:\t%x\n", p.ip_hdr.tos);
				printf("len:\t%x\n", ntohs(p.ip_hdr.tot_len));
				printf("id:\t%x\n", ntohs(p.ip_hdr.id));
				printf("frag:\t%x\n", ntohs(p.ip_hdr.frag_off));
				printf("ttl:\t%x\n", p.ip_hdr.ttl);
				printf("proto:\t%x\n", p.ip_hdr.protocol);
				printf("check:\t%x\n", p.ip_hdr.check);
				printf("saddr:\t%x\n", p.ip_hdr.saddr);//PRINT_IP("saddr:\t%x.%x.%x.%x\n", p.ip_hdr.saddr);
				printf("daddr:\t%x\n", p.ip_hdr.daddr);//PRINT_IP("daddr:\t%x.%x.%x.%x\n", p.ip_hdr.daddr);

				printf("type:\t%x\n", p.pl.type);
				printf("code:\t%x\n", p.pl.code);
				printf("chsum:\t%x\n", p.pl.csum);
				printf("group:\t%x\n", ntohl(p.pl.group));//PRINT_IP("group:\t%x.%x.%x.%x\n", ntohl(p.pl.group));
				printf("\n");
		} while (1);

		//start = time(NULL);
		//if (p.pl.group == 0) handle_general_query(groups, ifname, p, start);
		//if (IS_MCAST(p.pl.group)) handle_group_spec_query(groups, ifname, &p);
	}
	close(sd);
	return 0;
}

void * cli(void *arg)
{
	uint32_t        * groups = ((CLI_DATA *)arg)->groups;
	char            * ifname = ((CLI_DATA *)arg)->ifname;
	pthread_mutex_t * l      = ((CLI_DATA *)arg)->l;
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
			if (-1 != search_group(groups, inet_addr(argument))) printf("group %s already added\n", argument);
			else if (!add_group(groups, inet_addr(argument))) printf("add failed, del some group first\n");
			else send_report(groups, ifname, inet_addr(argument));
			pthread_mutex_unlock(l);
		}
		else if (1 == sscanf(command, "del %s", argument))
		{
			if (0 != check_ip(argument)) continue;
			pthread_mutex_lock(l);
			if (del_group(groups, inet_addr(argument)))
			{
				printf("group %s deleted\n", argument);
				send_leave(groups, ifname, inet_addr(argument));
			}
			else printf("group %s not found\n", argument);
			pthread_mutex_unlock(l);
		}
		else if (0 == strncmp(command, "exit", CMD_LEN))
		{
			status = 0;
		}
		else if (command[0] == '\n') 
		{
			printf("%s", command);
			fflush(stdin);
			continue;
		}
		else CLI_USAGE(command);
	} while (status);
	//TODO stop client
	//pthread_exit(NULL);
	exit(0);
}

int main (int argc, char **argv)
{
	srand(time(NULL));
	mtrace();
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

	uint32_t * groups = (uint32_t *)malloc(GROUP_COUNT * sizeof(uint32_t));
	struct timeval * timers = (struct timeval *)malloc(GROUP_COUNT * sizeof(struct timeval));
	memset(groups, 0, GROUP_COUNT * sizeof(uint32_t));


	pthread_t tcli, thgq;
	pthread_mutex_t lock;
	pthread_mutex_init(&lock, NULL);
	CLI_DATA cli_data ={groups, ifname, &lock};
	HGQ_DATA hgq_data ={groups, timers, ifname, NULL, time(NULL)};

	if (bflag)
	{
		if(0 != fill_groups(groups, ipstr, ipend, eflag)) return -1;
		if(0 != refresh_timers(timers, groups)) return -1;
		if(0 != pthread_create(&thgq, NULL, handle_general_query, (void *)&hgq_data))
		{
			fprintf(stderr,"%spthread_create failed:%s\n", argv[0], (errno ? strerror(errno) : "ok"));
			return -1;
		}
	}

	//cli(groups, ifname);
	if(0 != pthread_create(&tcli, NULL, cli, (void *)&cli_data))
	{
		fprintf(stderr,"%spthread_create failed:%s\n", argv[0], (errno ? strerror(errno) : "ok"));
		return -1;
	}
	listen_queries(groups, ifname);
	free(groups);
	pthread_mutex_destroy(&lock);
	return 0;
}
