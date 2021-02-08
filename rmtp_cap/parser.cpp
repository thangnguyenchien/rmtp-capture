#include "parser.h"
#include "types.h"

types::TCP_PACKET TCPParser::GetDataStructure()
{
	return this->currentPkt;
}

bool TCPParser::ParseRawData(const unsigned char* raw_data, int len)
{
	if (raw_data == NULL)
	{
		return FALSE;
	}
	this->pDataBuff = (unsigned char*)raw_data + SKIP_DATALINK_BYTES;
	this->currentPkt.ip_header = *(types::P_IP_HEADER)this->pDataBuff;
	this->pDataBuff += sizeof(types::IP_HEADER) -
		((this->currentPkt.ip_header.ver_ihl & 0x0f) > 5 ? 0 : 4);
	this->currentPkt.tcp_header = *(types::P_TCP_HEADER)this->pDataBuff;
	this->currentPkt.tcp_header.src_port = ntohs(this->currentPkt.tcp_header.src_port);
	this->currentPkt.tcp_header.dest_port = ntohs(this->currentPkt.tcp_header.dest_port);
	this->currentPkt.tcp_header.seq_number = ntohl(this->currentPkt.tcp_header.seq_number);
	this->currentPkt.tcp_header.header_len = ntohl(this->currentPkt.tcp_header.header_len);
	this->currentPkt.tcp_header.window = ntohs(this->currentPkt.tcp_header.window);
	this->currentPkt.tcp_header.urgent_ptr = ntohs(this->currentPkt.tcp_header.urgent_ptr);
	return TRUE;
}
/*
static void ConvertNetworkByteToHostByte(void* pSrcBuff, void* pDestBuff, int buffSize, int byteSize)
{
	register int i;
	switch (byteSize)
	{
	case 2:
		for (i = 0; i < buffSize; i += byteSize)
		{
			pDestBuff[i] = ntohs((u_short)(pSrcBuff[i]));
		}
		break;
	case 4:
		for (i = 0; i < buffSize; i += byteSize)
		{
			pDestBuff[i] = ntohl((u_int)pSrcBuff[i]);
		}
		break;
	case 8:
		for (i = 0; i < buffSize; i += byteSize)
		{
			pDestBuff[i] = ntohll((u_int64)pSrcBuff[i]);
		}
		break;
	}
}*/
