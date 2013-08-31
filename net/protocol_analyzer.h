#ifndef NET_PROTOCOL_ANALYZER_H
#define NET_PROTOCOL_ANALYZER_H

#include <time.h>
#include "net/connection.h"
#include "net/packet.h"

namespace net {
	class protocol_analyzer {
		public:
			virtual bool process(time_t t, connection* conn, const packet& pkt) = 0;
	};
}

#endif // NET_PROTOCOL_ANALYZER_H
