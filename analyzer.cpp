#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "analyzer.h"
#include "sniffer.h"

extern sniffer sniffer;

bool analyzer::process(time_t t, const struct iphdr* ip_header, const struct tcphdr* tcp_header, const unsigned char* payload, size_t len)
{
	unsigned short srcport = ntohs(tcp_header->source);
	unsigned short destport = ntohs(tcp_header->dest);

	if ((srcport == 80) || (destport == 80) || (srcport == 8080) || (destport == 8080) || (srcport == 8000) || (destport == 8000)) {
		return process_http(t, ip_header, payload, len);
	}

	return true;
}

bool analyzer::process_http(time_t t, const struct iphdr* ip_header, const unsigned char* payload, size_t len)
{
	const unsigned char* ptr = payload;
	const unsigned char* end = payload + len;

	const char* method = NULL;
	size_t methodlen = 0;
	const char* path = NULL;
	size_t pathlen = 0;
	const char* host = NULL;
	size_t hostlen = 0;

	int state = 0;

	do {
		unsigned char c = *ptr;

		switch (state) {
			case 0: // Before method.
				if ((c >= 'A') && (c <= 'Z')) {
					method = (const char*) ptr;
					methodlen = 1;

					state = 1; // Method.
				} else if ((c != ' ') && (c != '\t') && (c != '\r') && (c != '\n')) {
					// Ignore invalid request.
					return true;
				}

				break;
			case 1: // Method.
				if ((c >= 'A') && (c <= 'Z')) {
					methodlen++;
				} else if ((c == ' ') || (c == '\t')) {
					state = 2; // Before path.
				} else {
					// Ignore invalid request.
					return true;
				}

				break;
			case 2: // Before path.
				if (c > ' ') {
					path = (const char*) ptr;
					pathlen = 1;

					state = 3; // Path.
				} else if ((c != ' ') && (c != '\t')) {
					// Ignore invalid request.
					return true;
				}

				break;
			case 3: // Path.
				if (c > ' ') {
					pathlen++;
				} else if ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n')) {
					if ((pathlen > 7) && (strncasecmp(path, "http://", 7) == 0)) {
						return sniffer.get_http_logger()->log(t, ip_header->saddr, method, methodlen, path, pathlen);
					}

					size_t left = len - (ptr - payload);
					if ((ptr = (const unsigned char*) memmem(ptr, left, "Host:", 5)) == NULL) {
						// Host header might come in the next packet.
						return true;
					} else {
						if ((ptr += 5) == end) {
							// Host header might come in the next packet.
							return true;
						}

						state = 4; // Before host.

						continue;
					}
				} else {
					// Ignore invalid request.
					return true;
				}

				break;
			case 4: // Before host.
				if (c > ' ') {
					host = (const char*) ptr;
					hostlen = 1;

					state = 5; // Host.
				} else if ((c != ' ') && (c != '\t')) {
					// Ignore invalid request.
					return true;
				}

				break;
			case 5: // Host.
				if (c > ' ') {
					hostlen++;
				} else if ((c == '\r') || (c == '\n') || (c == ' ') || (c == '\t')) {
					return sniffer.get_http_logger()->log(t, ip_header->saddr, method, methodlen, host, hostlen, path, pathlen);
				} else {
					// Ignore invalid request.
					return true;
				}

				break;
		}

		ptr++;
	} while (ptr < end);

	return true;
}
