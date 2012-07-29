#ifndef ANALYZER_H
#define ANALYZER_H

#include <netinet/tcp.h>

class analyzer {
	public:
		// Process packet.
		static bool process(const struct tcphdr* tcp_header, const unsigned char* payload, size_t len);

	protected:
		static bool process_http(const unsigned char* payload, size_t len);
};

#endif // ANALYZER_H
