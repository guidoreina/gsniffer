#include <stdlib.h>
#include "packet_processor.h"

bool packet_processor::process(time_t t, const connection* conn, const unsigned char* payload, size_t len)
{
	unsigned short srcport = conn->srcport;
	unsigned short destport = conn->destport;

	if ((srcport == 80) || (destport == 80) || (srcport == 8080) || (destport == 8080) || (srcport == 8000) || (destport == 8000)) {
		if (conn->first_upload) {
			return _M_http_analyzer.process(t, conn, payload, len);
		}
	}

	return true;
}