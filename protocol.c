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

int build_ip_header(struct iphdr * ip_h, char * ifname, uint32_t daddr)
{
	memset(ip_h, 0, sizeof(struct iphdr));

	ip_h->version   =  0x4;//IPVERSION;
	ip_h->ihl = 0x6;
	ip_h->tos = 0;
	ip_h->tot_len  = htons(sizeof(struct igmp_pack));
	ip_h->frag_off = 0;
	ip_h->id = 0;
	ip_h->ttl = TTL_IGMP;
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

int init_raw_socket(char * ifname)
{
	int s = 0;
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

	if (0 > (s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)))
	{
		perror ("socket() failed ");
		return -1;
	}

	if (0 > setsockopt (s, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)))
	{
		perror ("setsockopt() failed to set IP_HDRINCL ");
		close(s);
		return -1;
	}

	if (0 > setsockopt (s, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (struct ifreq)))
	{
		perror ("setsockopt() failed to bind to interface ");
		close(s);
		return -1;
	}

	return s;
}

int socket_filtering_igmp(char * ifname)
{
	int s;
	if (0 > (s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))))
		{
			fprintf(stderr,"%s socket failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
			return -1;
		}

		struct sockaddr_ll addr;
		memset(&addr, 0, sizeof(addr));
		addr.sll_ifindex = if_nametoindex(ifname);
		addr.sll_family = PF_PACKET;
		addr.sll_protocol = htons(ETH_P_ALL);
		if (bind(s, (struct sockaddr *) &addr, sizeof(addr)))
		{
			fprintf(stderr,"%s bind failed:%s\n", __func__, (errno ? strerror(errno) : "ok"));
			close(s);
			return -1;
		}

		static struct sock_filter bpfcode[FLEN] = {
			/*recive IGMP ONLY */
			{ OP_LDH, 0, 0, 12           },	/* get l2 proto num */
			{ OP_JEQ, 0, 5, ETH_P_IP     },	/* drop if !ETH_P_IP */
			{ OP_LDB, 0, 0, 22           },	/* get TTL */
			{ OP_JEQ, 0, 3, TTL_IGMP     },	/* drop if TTL != 1 */
			{ OP_LDB, 0, 0, 23           },	/* get l3 proto num */
			{ OP_JEQ, 0, 1, IPPROTO_IGMP },	/* drop if !IPPROTO_IGMP */
			{ OP_RET, 0, 0, 0xFFFF       },	/* return packet */
			{ OP_RET, 0, 0, 0            }, /* drop packet */
		};

		struct sock_fprog bpf = { FLEN, bpfcode };
		if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)))
		{
			fprintf(stderr,"%s setsockopt SO_ATTACH_FILTER:%s\n", __func__, (errno ? strerror(errno) : "ok"));
			close(s);
			return -1;
		}

		struct packet_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.mr_type = PACKET_MR_PROMISC;
		mreq.mr_ifindex = if_nametoindex(ifname);

		if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)))
		{
			fprintf(stderr,"%s setsockopt PACKET_ADD_MEMBERSHIP:%s\n", __func__, (errno ? strerror(errno) : "ok"));
			close(s);
			return -1;
		}
	return s;
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

int send_igmp_pack(int s, struct igmp_pack * p)
{
	p->ra1 = IPOPT_RA;
	p->ra2 = IPOPT_MINOFF;
	p->ra34 = IPOPT_OPTVAL;
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(struct sockaddr_in));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = p->ph.daddr;
	
	return (sizeof(igmp_pack) == sendto(s, p, sizeof(igmp_pack), 0, (struct sockaddr *) &dst, sizeof (struct sockaddr)));
}

int build_igmp_report(struct igmp_pack * p, char * ifname, uint32_t ip)
{
	memset(p, 0, sizeof(igmp_pack));

	if (0 != build_ip_header(&p->ph, ifname, ip))
	{
		fprintf(stderr,"'%s': build_ip_header() failed!\n", __func__);
		return -1;
	}
	if (0 != build_igmp_pl(&p->pl, IGMP_V2_MEMBERSHIP_REPORT, 0, ip))
	{
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", __func__);
		return -1;
	}

	return 0;
}

int build_igmp_leave(struct igmp_pack * p, char * ifname, uint32_t ip)
{
	memset(p, 0, sizeof(igmp_pack));

	if (0 != build_ip_header(&p->ph, ifname, LEAVE_DST_ADDR))
	{
		fprintf(stderr,"'%s': build_ip_header() failed!\n", __func__);
		return -1;
	}
	if (0 != build_igmp_pl(&p->pl, IGMP_V2_LEAVE_GROUP, 0, ip))
	{
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", __func__);
		return -1;
	}

	return 0;
}
