#ifndef PROTOCOL_ANALYZER_H
#define PROTOCOL_ANALYZER_H

#include <time.h>
#include "connection.h"

class protocol_analyzer {
	public:
		virtual bool process(time_t t, const connection* conn, const unsigned char* payload, size_t len) = 0;
};

#endif // PROTOCOL_ANALYZER_H
