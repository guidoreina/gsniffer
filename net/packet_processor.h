#ifndef NET_PACKET_PROCESSOR_H
#define NET_PACKET_PROCESSOR_H

#include "net/internet/http/analyzer.h"

namespace net {
	class packet_processor {
		public:
			// Process packet.
			bool process(time_t t, connection* conn, const packet& pkt);

		protected:
			internet::http::analyzer _M_http_analyzer;
	};
}

#endif // NET_PACKET_PROCESSOR_H
