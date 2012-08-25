#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include "http_analyzer.h"

class packet_processor {
	public:
		// Process packet.
		bool process(time_t t, const connection* conn, const unsigned char* payload, size_t len);

	protected:
		http_analyzer _M_http_analyzer;
};

#endif // PACKET_PROCESSOR_H
