#include "packet.h"

void parse_tcp_packet(P_TCP_PACKET packet_out,const unsigned char* packet_raw, int packet_size)
{
	unsigned int offset;
	//To skip datalink layer, advance the offset to 14 bytes
	offset = 14;
	packet_out->ip_header = *(P_IP_HEADER)(packet_raw + offset);
	//If IHL > 5 we substract the Option field will not be used so we substract the ip header size by 4
	offset += sizeof(IP_HEADER) - ((packet_out->ip_header.ver_ihl & 0x0f) > 5 ? 0 : 4);
	packet_out->tcp_header = *(P_TCP_HEADER)(packet_raw + offset);
}