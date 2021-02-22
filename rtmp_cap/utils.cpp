#include "utils.h"

u_char *duplicate(const u_char* data, int size)
{
	u_char* buff;
	if ((buff = (u_char*)malloc(size)) == NULL)
	{
		return NULL;
	}
	memcpy_s(buff, size, data, size);
	return buff;
}

void copy(u_char* dst, u_char* src, size_t size)
{
	register u_int i;
	for (i = 0; i < size; i++)
	{
		*(dst + i) = *(src + i);
	}
}