#ifndef HTTP_ANALYZER_H
#define HTTP_ANALYZER_H

#include "protocol_analyzer.h"

class http_analyzer : public protocol_analyzer {
	public:
		bool process(time_t t, connection* conn, const packet& pkt);

	protected:
		static const size_t METHOD_MAX_LEN;
		static const size_t HOST_MAX_LEN;
		static const size_t PATH_MAX_LEN;

		static const size_t REQUEST_MAX_LEN;
};

#endif // HTTP_ANALYZER_H
