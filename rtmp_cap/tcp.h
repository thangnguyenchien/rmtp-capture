#pragma once
#include "utils.h"
#include "types.h"
#include "config.h"
#include <vector>
#define DECAP_IN_ADDR_ULONG(addr) ((addr).S_un.S_addr)
//source: https://www.tcpdump.org/pcap.html
namespace network
{
	/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct ethernet_header
	{
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct ip_header
	{
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src, ip_dst; /* source and dest address */
	};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct tcp_header
	{
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
	};

	/*TCP packet*/
	struct tcp_packet
	{
		int packet_id;
		struct ethernet_header* p_ether_header;
#define ETHERNET_HEADER_SIZE 14
		struct ip_header* p_ip_header;
		int ip_header_size;
		struct tcp_header* p_tcp_header;
		int tcp_header_size;
		int packet_appli_flag;
		u_char* payload;
		int payload_size;
	};

	struct stream_ip_pair {
		struct in_addr ip_p1, ip_p2;
	};

	struct raw_packet
	{
		int packet_len;
		u_char* packet_raw;
	};

	typedef std::vector<network::raw_packet> PACKET_PAGE;

	class TCPStream
	{
	private:
		int payload_size;
		int has_proto;
		network::stream_ip_pair* ip_pair;
		std::vector<network::tcp_packet*> packet_list;
		void analyze_packet(network::tcp_packet* packet);
	public:
		int stream_id;
		~TCPStream();
		TCPStream();
		void reassemble_payload();
		void get_stream_info();
		bool compare_ip_pair(ULONG ul_ip_p1, ULONG ul_ip_p2);
		void add_packet_to_stream(network::tcp_packet* pkt);
	};

	class StreamManager
	{
	private:
		int stream_count;
	public:
		std::vector<network::TCPStream*> stream_list;
		StreamManager();
		~StreamManager();
		network::TCPStream* get_stream_by_ip_pair(ULONG ul_ip_p1, ULONG ul_ip_p2);
		void add_new_stream(network::TCPStream* stream);
		int get_stream_count();
	};

	class TCPStreamAnalyzer
	{
	private:
		std::vector<network::tcp_packet> pkt_list;
		network::StreamManager* stream_man;
		int packet_count;
		void page_to_tcp_packet_list(PACKET_PAGE tcp_page);
		void find_stream();
	public:
		~TCPStreamAnalyzer();
		TCPStreamAnalyzer(network::StreamManager* manager);
		TCPStreamAnalyzer();
		void set_mamager(network::StreamManager* manager);
		std::vector<network::TCPStream*> analyze(pcap_t* adhandle, int packet_count);
		std::vector<network::TCPStream*> analyze(PACKET_PAGE tcp_page);
	};

	void proto_info(int proto_flag);
 	void parse_tcp_packet(network::tcp_packet* packet_out, u_char* packet_raw, int packet_size);
	void free_page(PACKET_PAGE page);
};


