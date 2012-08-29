#ifndef PROTOCOL_ANALYZER_H
#define PROTOCOL_ANALYZER_H

#include <time.h>
#include "connection.h"
#include "packet.h"

class protocol_analyzer {
	public:
		virtual bool process(time_t t, connection* conn, const packet& pkt) = 0;
};

#endif // PROTOCOL_ANALYZER_H
