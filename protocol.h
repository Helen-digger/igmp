#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define _POSIX_C_SOURCE >= 199309L
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <mcheck.h>
#include <signal.h>

#include <arpa/inet.h>
//#include <netinet/in.h>
#include <netinet/igmp.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include <linux/types.h>
#include <linux/if.h>
//#include <linux/llc.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/igmp.h>
#include <linux/ip.h>

#include <sys/time.h>
//#include <linux/time.h>

#include <time.h>
#include <features.h>


#include "tbf.h"


#define GROUP_COUNT 20480
#define LEAVE_DST_ADDR inet_addr("224.0.0.2")
#define GENERAL_DST_ADDR inet_addr("224.0.0.1")

#define GENERAL_MCAST_ADDR 0 //"0.0.0.0"

#define IGMP_GQUERY_CODE 0x64
#define IGMP_SQUERY_CODE 0x64

typedef struct igmp_pack
{
	struct iphdr   ip_hdr;
	struct igmphdr pl;
} igmp_pack;

typedef struct iphdr_fixed {
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ihl:4,
		version:4;
	__u8	tos;
	__sum16	check;
	__u8	ttl;
	__u8	protocol;
	__be32	saddr;
	__be32	daddr;
} iphdr_fixed;


typedef struct igmp_frame
{
	struct ethhdr  frame_hdr;
	//unsigned char sh[2];
	struct iphdr_fixed ip_hdr;
	struct igmphdr pl;
	//unsigned char a[100];
} igmp_frame;

unsigned short in_cksum(unsigned short *addr, int len);

int init_ip_header(struct iphdr * ip_h, char * ifname, uint32_t daddr);

int build_igmp_pl(struct igmphdr * igmp, __u8 type, __u8 time, uint32_t daddr);

int init_raw_socket(int * s, char * ifname);

int check_ip(char * ip_str);

#define IS_MCAST(_ip_) ((_ip_ & 0x000000f0) != 0x000000e0)
#define PRINT_IP(_s_, _ip_) printf(_s_, (_ip_)&0xff, (_ip_>>8)&0xff, (_ip_>>16)&0xff, (_ip_>>24)&0xff);
#define PRINT_MAC(_s_, _m_) printf(_s_, _m_[0], _m_[1], _m_[2], _m_[3], _m_[4], _m_[5]);

#define INIT_SOCK(_s_,_if_) do { \
	if (0 != init_raw_socket(&_s_, _if_)) \
	{ \
		fprintf(stderr,"'%s': init_raw_socket() failed!\n", "MACRO: B_GQUERY"); \
		/*return -1;*/ \
	} \
} while (0)

#define SEND_PACK(_s_,_p_) do { \
	struct sockaddr_in dst; \
	memset(&dst, 0, sizeof(struct sockaddr_in)); \
	dst.sin_family = AF_INET; \
	dst.sin_addr.s_addr = _p_.ip_hdr.daddr; \
	\
	if (sizeof(_p_) != sendto(_s_, &_p_, sizeof(_p_), 0, (struct sockaddr *) &dst, sizeof (struct sockaddr))) \
	{ \
		fprintf(stderr,"'%s': sendto() failed!\n", "MACRO: B_GQUERY"); \
		/*return -1;*/ \
	} \
} while (0)

	//IGMP_HOST_MEMBERSHIP_QUERY
	//IGMPV2_HOST_MEMBERSHIP_REPORT
	//IGMP_HOST_LEAVE_MESSAGE

#define BLD_REPORT(_p_,_if_,_ip_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ip_hdr, _if_, _ip_)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_REPORT"); \
		/*return -1;*/ \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMPV2_HOST_MEMBERSHIP_REPORT, 0, _ip_)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_REPORT"); \
		/*return -1;*/ \
	} \
} while (0)

#define BLD_LEAVE(_p_,_if_,_ip_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ip_hdr, _if_, LEAVE_DST_ADDR)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_LEAVE"); \
		return -1; \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMP_HOST_LEAVE_MESSAGE, 0, _ip_)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_LEAVE"); \
		return -1; \
	} \
} while (0)

#define BLD_GQUERY(_p_,_if_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ip_hdr, _if_, GENERAL_DST_ADDR)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_GQUERY"); \
		return -1; \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMP_HOST_MEMBERSHIP_QUERY, IGMP_GQUERY_CODE, GENERAL_MCAST_ADDR)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_GQUERY"); \
		return -1; \
	} \
} while (0)

#define BLD_GRSQUERY(_p_,_if_,_ip_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ip_hdr, _if_, GENERAL_DST_ADDR)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_GRSQUERY"); \
		return -1; \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMP_HOST_MEMBERSHIP_QUERY, IGMP_SQUERY_CODE, _ip_)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_GRSQUERY"); \
		return -1; \
	} \
} while (0)
