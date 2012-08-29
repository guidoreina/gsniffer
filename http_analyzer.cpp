#include <stdlib.h>
#include <string.h>
#include "http_analyzer.h"
#include "sniffer.h"

const size_t http_analyzer::METHOD_MAX_LEN = 20;
const size_t http_analyzer::HOST_MAX_LEN = 256;
const size_t http_analyzer::PATH_MAX_LEN = 8 * 1024;

const size_t http_analyzer::REQUEST_MAX_LEN = 16 * 1024;

extern sniffer sniffer;

bool http_analyzer::process(time_t t, connection* conn, const packet& pkt)
{
	if ((pkt.direction == INCOMING_PACKET) || (conn->state == 7)) {
		return true;
	}

	const unsigned char* begin;

	if ((!conn->out) || (conn->out->count() == 0)) {
		begin = pkt.payload;
	} else {
		if (!conn->append_out((const char*) pkt.payload, pkt.len)) {
			return false;
		}

		begin = (const unsigned char*) conn->out->data() + (conn->uploaded - pkt.len);
	}

	const unsigned char* ptr = begin;
	const unsigned char* end = ptr + pkt.len;

	size_t methodlen = conn->protocol.http.methodlen;
	size_t pathlen = conn->protocol.http.pathlen;
	size_t hostlen = conn->protocol.http.hostlen;

	size_t left;

	int state = conn->state;

	do {
		unsigned char c = *ptr;

		switch (state) {
			case 0: // Before method.
				if ((c >= 'A') && (c <= 'Z')) {
					conn->protocol.http.method = conn->uploaded - (end - ptr);
					methodlen = 1;

					state = 1; // Method.
				} else if ((c != ' ') && (c != '\t') && (c != '\r') && (c != '\n')) {
					// Ignore invalid request.
					conn->state = 7;
					return true;
				}

				break;
			case 1: // Method.
				if ((c >= 'A') && (c <= 'Z')) {
					if (++methodlen > METHOD_MAX_LEN) {
						// Ignore invalid request.
						conn->state = 7;
						return true;
					}
				} else if ((c == ' ') || (c == '\t')) {
					state = 2; // Before path.
				} else {
					// Ignore invalid request.
					conn->state = 7;
					return true;
				}

				break;
			case 2: // Before path.
				if (c > ' ') {
					conn->protocol.http.path = conn->uploaded - (end - ptr);
					pathlen = 1;

					state = 3; // Path.
				} else if ((c != ' ') && (c != '\t')) {
					// Ignore invalid request.
					conn->state = 7;
					return true;
				}

				break;
			case 3: // Path.
				if (c > ' ') {
					if (++pathlen > PATH_MAX_LEN) {
						// Ignore invalid request.
						conn->state = 7;
						return true;
					}
				} else if ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n')) {
					const char* method;
					const char* path;
					if ((!conn->out) || (conn->out->count() == 0)) {
						method = (const char*) begin + conn->protocol.http.method;
						path = (const char*) begin + conn->protocol.http.path;
					} else {
						method = conn->out->data() + conn->protocol.http.method;
						path = conn->out->data() + conn->protocol.http.path;
					}

					if ((pathlen > 7) && (strncasecmp(path, "http://", 7) == 0)) {
						if (!sniffer.get_http_logger()->log(t, conn->srcip, method, methodlen, path, pathlen)) {
							return false;
						}

						conn->state = 7;
						return true;
					}

					state = 4; // Searching host.
				} else {
					// Ignore invalid request.
					conn->state = 7;
					return true;
				}

				break;
			case 4: // Searching host.
				if ((conn->out) && (conn->out->count() > 0)) {
					ptr = (const unsigned char*) conn->out->data() + conn->protocol.http.path + conn->protocol.http.pathlen;
				}

				left = end - ptr;
				if ((ptr = (const unsigned char*) memmem(ptr, left, "Host:", 5)) == NULL) {
					// Host header might come in the next packet.
					ptr = end;

					continue;
				} else {
					ptr += 5;

					state = 5; // Before host value.

					continue;
				}

				break;
			case 5: // Before host value.
				if (c > ' ') {
					conn->protocol.http.host = conn->uploaded - (end - ptr);
					hostlen = 1;

					state = 6; // Host.
				} else if ((c != ' ') && (c != '\t')) {
					// Ignore invalid request.
					conn->state = 7;
					return true;
				}

				break;
			case 6: // Host.
				if (c > ' ') {
					if (++hostlen > HOST_MAX_LEN) {
						// Ignore invalid request.
						conn->state = 7;
						return true;
					}
				} else if ((c == '\r') || (c == '\n') || (c == ' ') || (c == '\t')) {
					const char* method;
					const char* host;
					const char* path;
					if ((!conn->out) || (conn->out->count() == 0)) {
						method = (const char*) begin + conn->protocol.http.method;
						host = (const char*) begin + conn->protocol.http.host;
						path = (const char*) begin + conn->protocol.http.path;
					} else {
						method = conn->out->data() + conn->protocol.http.method;
						host = conn->out->data() + conn->protocol.http.host;
						path = conn->out->data() + conn->protocol.http.path;
					}

					if (!sniffer.get_http_logger()->log(t, conn->srcip, method, methodlen, host, hostlen, path, pathlen)) {
						return false;
					}

					conn->state = 7;
					return true;
				} else {
					// Ignore invalid request.
					conn->state = 7;
					return true;
				}

				break;
		}

		ptr++;
	} while (ptr < end);

	// Request too large?
	size_t size = (conn->out ? conn->out->count() : 0);
	if (size + pkt.len > REQUEST_MAX_LEN) {
		// Ignore invalid request.
		conn->state = 7;
		return true;
	}

	// First packet?
	if ((!conn->out) || (conn->out->count() == 0)) {
		if (!conn->append_out((const char*) pkt.payload, pkt.len)) {
			return false;
		}
	}

	conn->state = state;

	conn->protocol.http.methodlen = methodlen;
	conn->protocol.http.pathlen = pathlen;
	conn->protocol.http.hostlen = hostlen;

	return true;
}
