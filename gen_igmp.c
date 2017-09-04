#include "protocol.h"

#define USAGE(_name_) fprintf(stderr, "Usage: %s -i <IFNAME> [-g] [-s <IP>]\n", _name_)

extern char *optarg;
extern int optin;
extern int opterr;
extern int optopt;

int main (int argc, char **argv)
{
	srand(time(NULL));
	unsigned char iflag = 0;
	unsigned char gflag = 0;
	unsigned char sflag = 0;
	char *ipstr = NULL;
	char *ifname = NULL;
	int c;

	while ((c = getopt (argc, argv, "i:gs:?")) != -1)
		switch (c)
		{
			case 'i':
				iflag = 1;
				ifname = optarg;
				break;
			case 'g':
				gflag = 1;
				break;
			case 's':
				sflag = 1;
				ipstr = optarg;
				if (0 != check_ip(ipstr)) return -1;
				break;
			case '?':
				if      (optopt == 'i')    fprintf (stderr, "Option -%c requires <IFNAME> argument.\n", optopt);
				else if (optopt == 's')    fprintf (stderr, "Option -%c requires <IP> argument.\n", optopt);
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

	int sd = 0;
	igmp_pack p;
	INIT_SOCK(sd, ifname);

	if (gflag)
	{
		BLD_GQUERY(p, ifname);
		SEND_PACK(sd, p);
	}

	if (sflag)
	{
		uint32_t daddr = inet_addr(ipstr);
		BLD_GRSQUERY(p, ifname, daddr);
		SEND_PACK(sd, p);
	}

#undef USAGE
	close(sd);
	return 0;
}
