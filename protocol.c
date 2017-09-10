#include "protocol.h"

unsigned short in_cksum(unsigned short *addr, int len)
{
	register int sum = 0;
	unsigned short answer = 0;
	register unsigned short *w = addr;
	register int nleft = len;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned short *) (&answer) = *(unsigned short *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

int init_ip_header(struct iphdr * ip_h, char * ifname, uint32_t daddr)
{
	memset(ip_h, 0, sizeof(struct iphdr));

	ip_h->version   =  0x4;//IPVERSION;
	ip_h->ihl = 0x6;
	ip_h->tos = 0;
	ip_h->tot_len  = htons(sizeof(struct igmp_pack));
	ip_h->frag_off = 0;
	ip_h->id = 0;
	ip_h->ttl = 1;
	ip_h->protocol   = IPPROTO_IGMP;
	ip_h->check = in_cksum((unsigned short *)ip_h, sizeof(struct iphdr));
	ip_h->saddr = 0;
	ip_h->daddr = daddr;
	return 0;
}

int build_igmp_pl(struct igmp * pl, u_int8_t igmp_type, u_int8_t time, uint32_t daddr)
{
	pl->igmp_type  = igmp_type;
	pl->igmp_code  = time;
	pl->igmp_group = (struct in_addr){daddr};
	pl->igmp_cksum = in_cksum((unsigned short *)pl, sizeof(*pl));
	return 0;
}

int init_raw_socket(int * s, char * ifname)
{
	const int on = 1;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (ioctl (fd, SIOCGIFINDEX, &ifr) < 0)
	{
		perror ("ioctl() failed ");
		return -1;
	}

	if (0 > (*s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)))
	{
		perror ("socket() failed ");
		return -1;
	}

	if (0 > setsockopt (*s, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)))
	{
		perror ("setsockopt() failed to set IP_HDRINCL ");
		return -1;
	}

	if (0 > setsockopt (*s, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (struct ifreq)))
	{
		perror ("setsockopt() failed to bind to interface ");
		return -1;
	}

	return 0;
}

int check_ip(char * ip_str)
{
	uint32_t ip = 0;
	if (1 != inet_pton(AF_INET, ip_str, &ip))
	{
		fprintf(stderr,"%s failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
		return -1;
	}
	if (IS_MCAST(ip))
	{
		fprintf(stderr,"%s failed:%s\n", __func__, "ip is not multicast");
		return -1;
	}
	return 0;
}

int isReadable(int sock, int * error, int timeOut)
{
	fd_set socketReadSet;
	FD_ZERO(&socketReadSet);
	FD_SET(sock, &socketReadSet);
	struct timeval tv;
	if (timeOut)
	{
		tv.tv_sec  = timeOut / 1000;
		tv.tv_usec = (timeOut % 1000) * 1000;
	}
	else
	{
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	}

	if (select(sock+1, &socketReadSet, 0, 0, &tv) == SOCKET_ERROR)
	{
		*error = 1;
		return 0;
	}

	*error = 0;
	return FD_ISSET(sock, &socketReadSet) != 0;
}
