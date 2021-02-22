#pragma once
#include "types.h"
#include <vector>

#define VALID_RMTP_VER 3
#define C0_S0_MESSAGE_SIZE 1
#define C1_S1_MESSAGE_SIZE 1536
#define C2_S2_MESSAGE_SIZE C1_S1_MESSAGE_SIZE
struct c0s0_packet
{
	u_char version;
};
struct c1s1_packet
{
	u_int time;
	u_int zero; //zero for c1/s1 packet
	u_char random_bytes[1528];
};
struct c2s2_packet
{
	u_int time;
	u_int time2;
	u_char random_bytes[1528];
};

bool validate_rmtp_version(c0s0_packet c0s0);

