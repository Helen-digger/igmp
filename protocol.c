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
	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		*(unsigned short *) (&answer) = *(unsigned short *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);  /* add hi 16 to low 16 */
	sum += (sum >> 16);                  /* add carry */
	answer = ~sum;                       /* truncate to 16 bits */
	return (answer);
}

int init_ip_header(struct iphdr * ip_h, char * ifname, uint32_t daddr)
{
	memset(ip_h, 0, sizeof(struct iphdr));

	ip_h->version   =  0x4;//IPVERSION;
	ip_h->ihl = 0x5;      /* Internet Control */
	ip_h->tos = 0;
	ip_h->tot_len  = htons(sizeof(struct igmp_pack));
	ip_h->frag_off = 0;
	ip_h->id = 0;//htons(0x0095);//TODO
	ip_h->ttl = 1;    /* applies to unicasts only */
	ip_h->protocol   = IPPROTO_IGMP;
	ip_h->check = in_cksum((unsigned short *)ip_h, sizeof(struct iphdr));

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	int fd = socket(PF_INET, SOCK_DGRAM, 0);
	strncpy( ifr.ifr_name , ifname, IFNAMSIZ);
	ioctl(fd, SIOCGIFADDR, &ifr);
	struct sockaddr_in * addr = (struct sockaddr_in *)&(ifr.ifr_addr);
	memcpy(&ip_h->saddr, &addr->sin_addr, sizeof(addr->sin_addr));
	close(fd);
/*#ifndef IGMP_GEN
	printf("%s %s\n", __func__, "client");
#else
	printf("%s %s\n", __func__, "gen");
	ip_h->saddr = 192 + (168 << 8) + ((rand() % 255) << 16) + ((1 + rand() % 254) << 24);
#endif*/
	ip_h->daddr = daddr;
	return 0;
}

int build_igmp_pl(struct igmphdr * igmp, __u8 type, __u8 time, uint32_t daddr)
{
	igmp->type  = type;
	igmp->code  = time;
	igmp->group = daddr;
	igmp->csum = in_cksum((unsigned short *)igmp, sizeof(struct igmphdr));
	return 0;
}

int init_raw_socket(int * s, char * ifname)
{
	const int on = 1;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
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

int handle_opts(void)
{
	;
	return 1;
}
