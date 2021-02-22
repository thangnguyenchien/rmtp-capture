#pragma once
#include <pcap.h>
#include "types.h"
#define DEFAULT_HEAP_SIZE 512
#define DEFAULT_ERROR_BUFF_SIZE 1024;
//this variable use to keep track of how many packet are captured during the run

void capure(pcap_t* adhandle, int packet_count);
