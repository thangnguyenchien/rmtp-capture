#include "types.h"
#include "tcp.h"

void parse_tcp_packet(tcp::MyTcpPacket* packet_out, const u_char* packet_raw, int packet_size)
{
	if (packet_out == NULL) 
		return;

	packet_out->payload = NULL;

	packet_out->p_ether_header = (tcp::ethernet_header*)(packet_raw);
	//To skip datalink layer, advance the offset to 14 bytes
	packet_out->p_ip_header = (tcp::ip_header*)(packet_raw + ETHERNET_HEADER_SIZE);
	packet_out->ip_header_size = IP_HL(packet_out->p_ip_header) * 4;
	if (packet_out->ip_header_size < MINIMUM_IP_HEADER_SIZE /* 20 */)
	{
#ifdef _DEBUG
		printf("invalid ip header len %d\n", packet_out->ip_header_size);
#endif
		return;
	}
	packet_out->p_tcp_header = (tcp::tcp_header*)(packet_raw + ETHERNET_HEADER_SIZE + packet_out->ip_header_size);
	packet_out->tcp_header_size = TH_OFF(packet_out->p_tcp_header) * 4;
	if (packet_out->tcp_header_size < MINIMUM_TCP_HEADER_SIZE)
	{
#ifdef _DEBUG
		printf("invalid tcp header len %d\n", packet_out->tcp_header_size);
#endif
		return;
	}

	packet_out->payload = (u_char*)(packet_raw + ETHERNET_HEADER_SIZE + packet_out->ip_header_size
		+ packet_out->tcp_header_size);

	packet_out->payload_size = packet_size - (ETHERNET_HEADER_SIZE + packet_out->ip_header_size
		+ packet_out->tcp_header_size);
}