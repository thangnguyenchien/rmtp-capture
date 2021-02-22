#include "rtmp.h"
#include "types.h"
bool validate_rmtp_version(c0s0_packet c0s0)
{
	return c0s0.version == VALID_RMTP_VER ? TRUE : FALSE;
}