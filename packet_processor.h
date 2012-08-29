#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include "http_analyzer.h"

class packet_processor {
	public:
		// Process packet.
		bool process(time_t t, connection* conn, const packet& pkt);

	protected:
		http_analyzer _M_http_analyzer;
};

#endif // PACKET_PROCESSOR_H
