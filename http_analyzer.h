#ifndef HTTP_ANALYZER_H
#define HTTP_ANALYZER_H

#include "protocol_analyzer.h"

class http_analyzer : public protocol_analyzer {
	public:
		bool process(time_t t, const connection* conn, const unsigned char* payload, size_t len);
};

#endif // HTTP_ANALYZER_H
