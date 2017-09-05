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
	__u8 f[100] = {0};
	igmp_frame * p = (igmp_frame *)f;
	if (0 > (sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))))
	{
		fprintf(stderr,"%s socket failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (ioctl (fd, SIOCGIFINDEX, &ifr) < 0)
	{
		perror ("ioctl() failed ");
		return -1;
	}

	if (0 > setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (struct ifreq)))
	{
		perror ("setsockopt() failed to bind to interface ");
		return -1;
	}

	ssize_t rcv;
	for(;;)
	{
		do {
			rcv = 0;
			memset(p, 0, sizeof(struct igmp_frame));
			if (0 >( rcv = recv(sd, f, sizeof(f), 0)))
			{
				fprintf(stderr,"%s recvfrom failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
				return -1;
			}
			
				printf("\n\nrecieved %lu , %lu\n", rcv, sizeof(p));

				PRINT_MAC("dhw:\t%02X:%02X:%02X:%02X:%02X:%02X\n",p->h_dest);
				PRINT_MAC("shw:\t%02X:%02X:%02X:%02X:%02X:%02X\n",p->h_source);
				printf("proto:\t%04X\n", ntohs(p->h_proto));

				printf("ihl:\t%01X\n", p->ihl);
				printf("ver:\t%01X\n", p->version);
				printf("tos:\t%02X\n", p->tos);
				printf("len:\t%u\n", ntohs(p->tot_len)); //printf("len:\t%04X\n", (p->tot_len));
				printf("id:\t%u\n", ntohs(p->id));
				printf("frag:\t%04X\n", ntohs(p->frag_off));
				printf("ttl:\t%02X\n", p->ttl);
				printf("proto:\t%02X\n", p->protocol);
				printf("check:\t%04X\n", ntohs(p->check));
				/*printf("saddr:\t%08X\n", p->saddr);*/PRINT_IP("saddr:\t%u.%u.%u.%u\n", p->saddr);
				/*printf("daddr:\t%08X\n", p->daddr);*/PRINT_IP("daddr:\t%u.%u.%u.%u\n", p->daddr);

				printf("ra1:\t%02X\n", p->ra1);
				printf("ra2:\t%02X\n", p->ra2);
				printf("ra34:\t%04X\n", ntohs(p->ra34));

				printf("type:\t%02X\n", p->type);
				printf("code:\t%02X\n", p->code);
				printf("chsum:\t%04X\n", p->csum);
				/*printf("group:\t%08X\n", p->group);*/PRINT_IP("group:\t%u.%u.%u.%u\n", ntohl(p->group));

				for(int i = 0; i< rcv; i++)
				{
					if (i>0 && i%16 == 0) printf("\n");
					if (i%8 == 0) printf("\t");
					printf("%02X ", f[i]);
				}
				printf("\n");
				if (p->type == IGMP_HOST_MEMBERSHIP_QUERY && p->h_proto == htons(ETH_P_IP)) break;
		} while (1);

		//start = time(NULL);
		//if (p->group == 0) handle_general_query(groups, ifname, p, start);
		//if (IS_MCAST(p->group)) handle_group_spec_query(groups, ifname, &p);
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
