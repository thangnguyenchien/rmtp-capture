#pragma once
#include <pcap.h>
#include "tcp.h"
#include "rtmp.h"
#include "utils.h"

//packet side
#define CLIENT_PACKET 0x10
#define SERVER_PACKET 0x20
//default rtmp port
#define RTMP_DEFAULT_TCP_PORT 1935
//protocol
#define PROTO_RTMPT  0x100001
#define PROTO_EMPTY 0x000001
