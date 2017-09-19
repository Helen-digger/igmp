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

#include "protocol.h"
#include "timers.h"

#define CMD_LEN 64
#define ARG_LEN 16
#define PPOLL_INTERVAL 1000000

#define USAGE(_name_) fprintf(stderr, "Usage: %s -i <IFNAME> -b <start-IP> [-e <end-IP>]\n", _name_)
#define CLI_ADD   "\tadd\t<IP> - add group\n"
#define CLI_DEL   "\tdel\t<IP> - delete group\n"
#define CLI_GROUP "\tgroups\tshow added groups\n"
#define CLI_TIMER "\ttimers\tshow active timers value\n"
#define CLI_EXIT  "\texit\tstop client and quit\n"
#define CLI_USAGE(_cmd_) fprintf(stderr, "invalid cmd:'%s'\nUsage:\n%s%s%s%s%s", \
                                 _cmd_, CLI_ADD, CLI_DEL, CLI_GROUP, CLI_TIMER, CLI_EXIT);

extern char * optarg;
extern int optin;
extern int opterr;
extern int optopt;

extern int group_count;

int fill_groups_by_args(
		struct timers * timers,
		char * ipstr,
		char * ipend,
		unsigned char bflag,
		unsigned char eflag)
{
	uint32_t b_ip = bflag ? ntohl(inet_addr(ipstr)) : 0;
	uint32_t e_ip = eflag ? ntohl(inet_addr(ipend)) : b_ip;
	struct timespec now = {0,0}, end = when_time_expires(IGMP_GQUERY_CODE);
	clock_gettime(CLOCK_REALTIME, &now);

	if (e_ip < b_ip || GROUP_COUNT < (e_ip - b_ip))
	{
		fprintf(stderr,"'%s': wrong ip range is set! it should be less %d\n", __func__, GROUP_COUNT);
		return -1;
	}

	for(uint32_t i = 0; i <= (e_ip - b_ip); i++)
	{
		timers[i].group = htonl(b_ip + i);
		timers[i].timer = gen_timer(end, now);
		group_count++;
	}
	return 0;
}

int send_if_bye(int sd, char * ifname, struct timers * timers)
{
	int sended = 0;
	igmp_pack p;

	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	for(int i = 0; i < GROUP_COUNT; i++)
	{
		if (timers[i].group && timer_is_set(timers[i].timer))
			if (is_time_to_send(now, timers[i].timer))
			{
				if (0 != build_igmp_report(&p, ifname, timers[i].group))
				{
					fprintf(stderr,"%s: send_igmp_pack failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
					return -1;
				}
				if (!send_igmp_pack(sd, &p))
				{
					fprintf(stderr,"%s: send_igmp_pack failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
					return -1;
				}
				drop_timer(&timers[i].timer);
				sended++;
			}
	}

	return sended;
}

int handle_cli_command(int sd, char * ifname, struct timers * timers, char * command)
{
	if (NULL == command) return -1;

	int invite(int rc)
	{
		fflush(stdin);
		printf("> ");
		return rc;
	}

	char argument[ARG_LEN];
	struct igmp_pack p;
	memset(argument, 0, ARG_LEN);
	memset(&p, 0, sizeof(struct igmp_pack));

	if (1 == sscanf(command, "add %s", argument))
	{
		if ( 0 != check_ip(argument)) return invite(-1);

		if (-1 != search_group(timers, inet_addr(argument)))
		{
			printf("group %s already added\n", argument);
		}
		else
		{
			if (0 != build_igmp_report(&p, ifname, inet_addr(argument)))
			{
				fprintf(stderr,"%s: send_igmp_pack failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
				return -1;
			}
			if (!send_igmp_pack(sd, &p))
			{
				fprintf(stderr,"%s: send_igmp_pack failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
				return -1;
			}
			if (!add_group(timers, inet_addr(argument)))
			{
				printf("add failed, del some group first\n");
			}
			printf("group %s added\n", argument);
		}

		return invite(0);
	}

	else if (1 == sscanf(command, "del %s", argument))
	{
		if (0 != check_ip(argument)) return invite(-1);

		if (del_group(timers, inet_addr(argument)))
		{
			if (0 != build_igmp_leave(&p, ifname, inet_addr(argument)))
			{
				fprintf(stderr,"%s: send_igmp_pack failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
				return -1;
			}
			if (!send_igmp_pack(sd, &p))
			{
				fprintf(stderr,"%s: send_igmp_pack failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
				return -1;
			}
			printf("group %s deleted\n", argument);
		}
		else printf("group %s not found\n", argument);

		return invite(0);
	}

	else if (0 == strncmp(command, "groups", CMD_LEN))
	{
		show_groups(timers);
		return invite(0);
	}

	else if (0 == strncmp(command, "timers", CMD_LEN))
	{
		show_timers(timers);
		return invite(0);
	}

	else if (0 == strncmp(command, "exit", CMD_LEN))
	{
		group_count = -1;
		return invite(0);
	}

	else if (command[0] == '\n' ||
	         command[1] == '\n' ||
	         command[0] == '\0')
	{
		return invite(0);
	}

	else
	{
		CLI_USAGE(command);
		return invite(-1);
	}

	return invite(1);
}

int main_loop(struct timers * timers, char * ifname)
{
	char command[CMD_LEN];

	int sd_snd = 0;
	int sd_rcv = 0;
	int search = 0;
	int ppoll_rc = 0;
	uint8_t buffer[BUFF_SIZE] = {0};
	igmp_pack * p = (igmp_pack *)(buffer + sizeof(struct ether_header));

	if (0 > (sd_snd = socket_cooked_igmp(ifname)))
	{
		fprintf(stderr,"%s: socket_cooked_igmp failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
		return -1;
	}
	if (0 > (sd_rcv = socket_filtering_igmp(ifname)))
	{
		fprintf(stderr,"%s socket_filtering_igmp failed%s\n", __func__, (errno ? strerror(errno) : "ok"));
		return -1;
	}

	ssize_t rcv;
	struct igmp * pl;

	struct pollfd fds[2] = {
		{STDIN_FILENO, POLLIN},
		{sd_rcv      , POLLIN},
	};

	printf("\n> ");
	fflush(stdout);
	struct timespec ppoll_timeout = {0, PPOLL_INTERVAL};
	do {
		ppoll_rc = ppoll(fds, 2, &ppoll_timeout, NULL);

		if (0 > ppoll_rc)
		{
			fprintf(stderr,"%s ppoll failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
			return -1;
		}

		if (fds[0].revents & POLLIN)
		{
			memset(command, 0, CMD_LEN);
			fflush(stdin);
			if (NULL != fgets(command, CMD_LEN, stdin))
			{
				for(int i = 0; i < CMD_LEN && command[i] != '\0'; i++)
				{
					if (command[i] == '\n') command[i] = '\0';
				}
				handle_cli_command(sd_snd, ifname, timers, command);
			}
			fflush(stdout);
		}

		if (fds[1].revents & POLLIN)
		{
			rcv = 0;
			search = -1;
			memset(buffer, 0, BUFF_SIZE);
			if (0 >( rcv = recv(sd_rcv, buffer, sizeof(buffer), 0)))
			{
				fprintf(stderr,"%s recvfrom failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
				continue;
			}

			pl =(struct igmp *)(buffer + sizeof(struct ether_header) + 4*p->ph.ihl);

			if (pl->igmp_type == IGMP_MEMBERSHIP_QUERY)
			{
				refresh_timers(timers, pl->igmp_group.s_addr, pl->igmp_code);
			}
			if (pl->igmp_type == IGMP_V2_MEMBERSHIP_REPORT)
			{
				search = search_group(timers, pl->igmp_group.s_addr);
				if (-1 != search) drop_timer(&timers[search].timer);
			}
		}

		send_if_bye(sd_snd, ifname, timers);

	} while (group_count > 0);

	printf("\n");
	close(sd_rcv);
	close(sd_snd);
	return 0;
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

	if (bflag)
	{
		if (0 != fill_groups_by_args(timers, ipstr, ipend, bflag, eflag)) return -1;
	}

	main_loop(timers, ifname);

	free(timers);
	return 0;
}
