#include "capturer.h"
#include "parser.h"
#include "types.h"
#include <pcap.h>

TCPCapturer::~TCPCapturer() {

}

TCPCapturer::TCPCapturer()
{
	this->callbackEnable = FALSE;
	this->stopCap = FALSE;
}

void TCPCapturer::EnableCallback(bool flag)
{
	this->callbackEnable = flag;
}

void TCPCapturer::SetDevice(pcap_if_t inf)
{
	this->captureInterface = inf;
}

bool TCPCapturer::BeginCapture(
								int snaplen, 
							    int flag, pcap_rmtauth* auth,
							    int timeout,
							    char* errbuf,
							    bool filter_enable, 
								filter::PCAP_FILTER* filter_in)
{

	if (((this->captureHandle = pcap_open(captureInterface.name, snaplen, flag, timeout, auth, errbuf)) == NULL))
	{
		return FALSE;
	}
	if (filter_enable)
	{
		//TODO: check prerequirements
	}
	while (!stopCap && this->tcpParser != NULL)
	{
		if (pcap_next_ex(this->captureHandle, &this->pPacketHeader, &this->pPacketBuffer) == 0)
		{
			//time out
			continue;
		}
		this->tcpParser->ParseRawData(this->pPacketBuffer, this->pPacketHeader->len);
		this->PrintPacketInfo(tcpParser->GetDataStructure());
	}
	return TRUE;
}

void TCPCapturer::StopCapture()
{
	this->stopCap = TRUE;
}

void TCPCapturer::SetParser(TCPParser* parser)
{

	this->tcpParser = parser;

}
void TCPCapturer::PrintPacketInfo(types::TCP_PACKET pkt)
{
	printf("\t\t**************\n");
	printf("src ip addr: %d.%d.%d.%d\n", pkt.ip_header.saddr.byte1, pkt.ip_header.saddr.byte2,
		pkt.ip_header.saddr.byte3, pkt.ip_header.saddr.byte4);
	printf("dst ip addr: %d.%d.%d.%d\n", pkt.ip_header.daddr.byte1, pkt.ip_header.daddr.byte2,
		pkt.ip_header.daddr.byte3, pkt.ip_header.daddr.byte4);
	printf("protocol number %d\n", pkt.ip_header.proto);
	printf("src port: %d\n", pkt.tcp_header.src_port);
	printf("dst port: %d\n", pkt.tcp_header.dest_port);
	printf("header len: %u\n", pkt.tcp_header.header_len);
	printf("sequence number: %u\n", pkt.tcp_header.seq_number);
	printf("data offset: %u\n", pkt.tcp_header.data_offset);
	printf("urgent ptr: %u\n", pkt.tcp_header.urgent_ptr);
}

pcap_t* TCPCapturer::GetCapturerHandle()
{
	return this->captureHandle;
}

bool TCPCapturer::CompileAndSetFilter(bpf_program* fcode_in, int netmask, char* filter)
{
	if ((pcap_compile(this->GetCapturerHandle(), fcode_in, filter, 1, netmask) < 0) && 
		(pcap_setfilter(this->GetCapturerHandle(), fcode_in) < 0 ))
	{
		return FALSE;
	}
	return TRUE;
}

