#include "types.h"
#include "tcp.h"

void parse_tcp_packet(types::P_TCP_PACKET packet_out,const unsigned char* packet_raw, int packet_size)
{
	unsigned int offset;
	//To skip datalink layer, advance the offset to 14 bytes
	offset = 14;
	packet_out->ip_header = *(types::P_IP_HEADER)(packet_raw + offset);
	//If IHL > 5 we substract the Option field will be used, if not we substract by the size of ip header by 4
	offset += sizeof(types::IP_HEADER) - ((packet_out->ip_header.ver_ihl & 0x0f) > 5 ? 0 : 4);
	packet_out->tcp_header = *(types::P_TCP_HEADER)(packet_raw + offset);
}