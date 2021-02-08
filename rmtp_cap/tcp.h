#pragma once
#include "types.h"
void parse_tcp_packet(types::P_TCP_PACKET packet_out, const unsigned char* packet, int packet_size);