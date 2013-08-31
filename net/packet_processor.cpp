#include <stdlib.h>
#include "net/packet_processor.h"

bool net::packet_processor::process(time_t t, connection* conn, const packet& pkt)
{
	switch (conn->srcport) {
		case 80:
		case 8000:
		case 8080:
			return _M_http_analyzer.process(t, conn, pkt);
		default:
			switch (conn->destport) {
				case 80:
				case 8000:
				case 8080:
					return _M_http_analyzer.process(t, conn, pkt);
			}
	}

	return true;
}
