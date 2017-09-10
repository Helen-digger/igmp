#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <features.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/igmp.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>

#include <linux/if.h>
#include <linux/filter.h>
#include <linux/bpf_common.h>

#define SOCKET_ERROR -1
#define BUFF_SIZE 128
#define GROUP_COUNT 128
#define LEAVE_DST_ADDR inet_addr("224.0.0.2")
#define GENERAL_DST_ADDR inet_addr("224.0.0.1")

#define GENERAL_MCAST_ADDR 0 //"0.0.0.0"

#define IGMP_MEMBERSHIP_QUERY		0x11	/* membership query         */
#define IGMP_V1_MEMBERSHIP_REPORT	0x12	/* Ver. 1 membership report */
#define IGMP_V2_MEMBERSHIP_REPORT	0x16	/* Ver. 2 membership report */
#define IGMP_V2_LEAVE_GROUP			0x17	/* Leave-group message	    */
#define IGMP_GQUERY_CODE 0x64
#define IGMP_SQUERY_CODE 0x64
#define MIN_IMGP_CODE 1

#define FLEN 6
#define OP_LDH (BPF_LD  | BPF_H   | BPF_ABS)
#define OP_LDB (BPF_LD  | BPF_B   | BPF_ABS)
#define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
#define OP_RET (BPF_RET | BPF_K)

struct igmp {
  u_int8_t igmp_type;             /* IGMP type */
  u_int8_t igmp_code;             /* routing code */
  u_int16_t igmp_cksum;           /* checksum */
  struct in_addr igmp_group;      /* group address */
};

typedef struct igmp_pack
{
	struct iphdr ph;
	u_int8_t     ra1;
	u_int8_t     ra2;
	u_int16_t    ra34;
	struct igmp  pl;
} igmp_pack;

unsigned short in_cksum(unsigned short *addr, int len);

int init_ip_header(struct iphdr * ip_h, char * ifname, uint32_t daddr);

int build_igmp_pl(struct igmp * pl, u_int8_t igmp_type, u_int8_t time, uint32_t daddr);

int init_raw_socket(int * s, char * ifname);

int check_ip(char * ip_str);

int isReadable(int sock, int * error, int timeOut);

#define IS_MCAST(_ip_) ((_ip_ & 0x000000f0) != 0x000000e0)
#define PRINT_IP(_s_, _ip_) printf(_s_, (_ip_)&0xff, (_ip_>>8)&0xff, (_ip_>>16)&0xff, (_ip_>>24)&0xff);
#define PRINT_MAC(_s_, _m_) printf(_s_, _m_[0], _m_[1], _m_[2], _m_[3], _m_[4], _m_[5]);

#define INIT_SOCK(_s_,_if_) do { \
	if (0 != init_raw_socket(&_s_, _if_)) \
	{ \
		fprintf(stderr,"'%s': init_raw_socket() failed!\n", "MACRO: INIT_SOCK"); \
		/*return -1;*/ \
	} \
} while (0)

#define INIT_FILTERING_SOCK(_s_,_if_) do { \
	if (0 > (_s_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) \
	{ \
		fprintf(stderr,"%s socket failed:%s\n", __func__, (errno ? strerror(errno) : "ok")); \
		return -1; \
	} \
 \
	struct sockaddr_ll addr; \
	memset(&addr, 0, sizeof(addr)); \
	addr.sll_ifindex = if_nametoindex(_if_); \
	addr.sll_family = PF_PACKET; \
	addr.sll_protocol = htons(ETH_P_ALL); \
	if (bind(_s_, (struct sockaddr *) &addr, sizeof(addr))) \
	{ \
		fprintf(stderr,"%s bind failed:%s\n", __func__, (errno ? strerror(errno) : "ok")); \
		return 1; \
	} \
 \
	static struct sock_filter bpfcode[FLEN] = { \
		/*recive IGMP ONLY */\
		{ OP_LDH, 0, 0, 12           },	/* get l2 proto num */\
		{ OP_JEQ, 0, 3, ETH_P_IP     },	/* drop if !ETH_P_IP */\
		{ OP_LDB, 0, 0, 23           },	/* get l3 proto num */\
		{ OP_JEQ, 0, 1, IPPROTO_IGMP },	/* drop if !IPPROTO_IGMP */\
		{ OP_RET, 0, 0, 0xFFFF       },	/* return packet */\
		{ OP_RET, 0, 0, 0            }, /* drop packet */\
	}; \
 \
	struct sock_fprog bpf = { FLEN, bpfcode }; \
	if (setsockopt(_s_, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) \
	{ \
		fprintf(stderr,"%s setsockopt SO_ATTACH_FILTER:%s\n", __func__, (errno ? strerror(errno) : "ok")); \
		return 1; \
	} \
 \
	struct packet_mreq mreq; \
	memset(&mreq, 0, sizeof(mreq)); \
	mreq.mr_type = PACKET_MR_PROMISC; \
	mreq.mr_ifindex = if_nametoindex(_if_); \
 \
	if (setsockopt(_s_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq))) \
	{ \
		fprintf(stderr,"%s setsockopt PACKET_ADD_MEMBERSHIP:%s\n", __func__, (errno ? strerror(errno) : "ok")); \
		return 1; \
	} \
} while (0)

#define SEND_PACK(_s_,_p_) do { \
	_p_.ra1 = IPOPT_RA; \
	_p_.ra2 = IPOPT_MINOFF; \
	_p_.ra34 = IPOPT_OPTVAL; \
	struct sockaddr_in dst; \
	memset(&dst, 0, sizeof(struct sockaddr_in)); \
	dst.sin_family = AF_INET; \
	dst.sin_addr.s_addr = _p_.ph.daddr; \
	\
	if (sizeof(_p_) != sendto(_s_, &_p_, sizeof(_p_), 0, (struct sockaddr *) &dst, sizeof (struct sockaddr))) \
	{ \
		fprintf(stderr,"'%s': sendto() failed!\n", "MACRO: SEND_PACK"); \
		/*return -1;*/ \
	} \
} while (0)


#define BLD_REPORT(_p_,_if_,_ip_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ph, _if_, _ip_)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_REPORT"); \
		/*return -1;*/ \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMP_V2_MEMBERSHIP_REPORT, 0, _ip_)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_REPORT"); \
		/*return -1;*/ \
	} \
} while (0)

#define BLD_LEAVE(_p_,_if_,_ip_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ph, _if_, LEAVE_DST_ADDR)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_LEAVE"); \
		return -1; \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMP_V2_LEAVE_GROUP, 0, _ip_)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_LEAVE"); \
		return -1; \
	} \
} while (0)

#define BLD_GQUERY(_p_,_if_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ph, _if_, GENERAL_DST_ADDR)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_GQUERY"); \
		return -1; \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMP_MEMBERSHIP_QUERY, IGMP_GQUERY_CODE, GENERAL_MCAST_ADDR)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_GQUERY"); \
		return -1; \
	} \
} while (0)

#define BLD_GRSQUERY(_p_,_if_,_ip_) do { \
	memset(&_p_, 0, sizeof(igmp_pack)); \
	\
	if (0 != init_ip_header(&_p_.ph, _if_, _ip_)) \
	{ \
		fprintf(stderr,"'%s': init_ip_header() failed!\n", "MACRO: BLD_GRSQUERY"); \
		return -1; \
	} \
	if (0 != build_igmp_pl(&_p_.pl, IGMP_MEMBERSHIP_QUERY, IGMP_SQUERY_CODE, _ip_)) \
	{ \
		fprintf(stderr,"'%s': build_igmp_pl() failed!\n", "MACRO: BLD_GRSQUERY"); \
		return -1; \
	} \
} while (0)
