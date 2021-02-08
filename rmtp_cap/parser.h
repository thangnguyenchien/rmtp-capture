#pragma once
#define SKIP_DATALINK_BYTES 14
#include "types.h"
template<typename T>
class IParser
{
public:
	virtual bool ParseRawData(const unsigned char* raw_data, int len) = 0;
	virtual T GetDataStructure() = 0;
protected:
	T currentPkt;
	const unsigned char* pDataBuff;
	int dataSize;
};

class TCPParser : IParser<types::TCP_PACKET>
{
public:
	types::TCP_PACKET GetDataStructure();
	bool ParseRawData(const unsigned char* raw_data, int len);
private:
 };