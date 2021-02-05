#pragma once
#include <pcap.h>
#define DATA_LINK_LAYER_OFFSET 14
#define U_INT_SIZE sizeof(u_int)
#define U_SHORT_SIZE sizeof(u_short)
#define U_CHAR_SIZE sizeof(u_char)
#define IP_ADDRESS_SIZE sizeof(ip_address)
/* 4 bytes IP address */
// byte1.byte2.byte3.byte4
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}IP_ADDRESS, *P_IP_ADDRESSS;

/* IPv4 header */
typedef struct ip_header {
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}IP_HEADER, *P_IP_HEADER;

/* UDP header*/
typedef struct udp_header {
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}UDP_HEADER, *P_UDP_HEADER;

/* My TCP header*/
typedef struct tcp_header {
	u_short dest_port;
	u_short src_port;
	u_int seq_number;
	u_int header_len;
	u_char data_offset;
	u_char revserve_flag[3];
	u_short window;
	u_short urgent_ptr;
} TCP_HEADER, *P_TCP_HEADER;

typedef struct tcp_packet {
	IP_HEADER ip_header;
	TCP_HEADER tcp_header;
	u_char* opt;
	u_char* data;
}TCP_PACKET, *P_TCP_PACKET;