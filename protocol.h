#ifndef _IGMP_PROTOCOL_H_
#define _IGMP_PROTOCOL_H_

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


#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <signal.h>
#include <poll.h>

#define SOCKET_ERROR -1
#define BUFF_SIZE 128
#define LEAVE_DST_ADDR inet_addr("224.0.0.2")
#define GENERAL_DST_ADDR inet_addr("224.0.0.1")

#define GENERAL_MCAST_ADDR 0 //"0.0.0.0"

#define IGMP_MEMBERSHIP_QUERY		0x11	/* membership query         */
#define IGMP_V1_MEMBERSHIP_REPORT	0x12	/* Ver. 1 membership report */
#define IGMP_V2_MEMBERSHIP_REPORT	0x16	/* Ver. 2 membership report */
#define IGMP_V2_LEAVE_GROUP			0x17	/* Leave-group message	    */
#define IGMP_GQUERY_CODE 0x64
#define IGMP_SQUERY_CODE 0x64
#define TTL_IGMP 1

#define FLEN 8
#define OP_LDW (BPF_LD  | BPF_W   | BPF_ABS)
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

int build_ip_header(struct iphdr * ip_h, char * ifname, uint32_t daddr);

int build_igmp_pl(struct igmp * pl, u_int8_t igmp_type, u_int8_t time, uint32_t daddr);

int init_raw_socket(char * ifname);

int socket_filtering_igmp(char * ifname);

int check_ip(char * ip_str);

int send_igmp_pack(int s, struct igmp_pack * p);

int build_igmp_report(struct igmp_pack * p, char * ifname, uint32_t ip);

int build_igmp_leave(struct igmp_pack * p, char * ifname, uint32_t ip);

#define IS_MCAST(_ip_) ((_ip_ & 0x000000f0) != 0x000000e0)
#endif
