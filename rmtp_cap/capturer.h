#pragma once
#include <pcap.h>
#include "parser.h"
#include "types.h"
class ICapturer
{
public:
	virtual void SetDevice(pcap_if_t inf) = 0;
	virtual bool BeginCapture(int snaplen, int flag, pcap_rmtauth* auth, int timeout, char* errbuf, bool filter_enable, filter::PCAP_FILTER* filter_in) = 0;
	virtual void StopCapture() = 0;
protected:
	//No thing here
};

class TCPCapturer : ICapturer
{
public:
	TCPCapturer();
	~TCPCapturer();
	void SetDevice(pcap_if_t inf);
	pcap_if_t GetDevice();
	void SetParser(TCPParser* parser);
	TCPParser* GetParser();
	pcap_t* GetCapturerHandle();
	void EnableCallback(bool flag);
	bool BeginCapture(int snaplen, int flag, pcap_rmtauth* auth, int timeout, char* errbuf, bool filter_enable, filter::PCAP_FILTER* filter_in);
	void StopCapture();
	void PrintPacketInfo(types::TCP_PACKET pkt);

private:
	virtual bool CompileAndSetFilter(bpf_program* fcode_in, int netmask, char* filter);
	pcap_pkthdr* pPacketHeader;
	const unsigned char* pPacketBuffer;
	TCPParser* tcpParser;
	pcap_if_t captureInterface;
	pcap_t* captureHandle;
	bool callbackEnable,
		stopCap;
};