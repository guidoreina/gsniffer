#ifndef ANALYZER_H
#define ANALYZER_H

#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

class analyzer {
	public:
		// Process packet.
		static bool process(time_t t, const struct iphdr* ip_header, const struct tcphdr* tcp_header, const unsigned char* payload, size_t len);

	protected:
		static bool process_http(time_t t, const struct iphdr* ip_header, const unsigned char* payload, size_t len);
};

#endif // ANALYZER_H
