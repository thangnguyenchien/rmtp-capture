#pragma once
#include "types.h"


void parse_tcp_packet(tcp::MyTcpPacket* packet_out, const u_char* packet_raw, int packet_size);