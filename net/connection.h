#ifndef NET_CONNECTION_H
#define NET_CONNECTION_H

#include <time.h>
#include <stdio.h>
#include <memory>
#include "net/ip_address.h"
#include "net/internet/http/headers.h"
#include "string/buffer.h"

namespace net {
	struct connection {
		static const size_t kInBufferAlloc = 512;
		static const size_t kOutBufferAlloc = 512;

		ip_address srcip;
		ip_address destip;
		unsigned short srcport;
		unsigned short destport;

		time_t creation;
		time_t timestamp; // Time last activity.

		off_t uploaded;
		off_t downloaded;

		string::buffer* in;
		string::buffer* out;

		unsigned char state:4;
		unsigned char direction:1; // 0: Outgoing, 1: Incoming.

		union {
			struct {
				internet::http::headers* server_headers;

				unsigned short method;
				unsigned short methodlen;

				unsigned short path;
				unsigned short pathlen;

				unsigned short host;
				unsigned short hostlen;

				unsigned short offset;

				unsigned short status_code;

				unsigned short substate:4;

				unsigned short major_number:4;
				unsigned short minor_number:4;

				// Parse server headers.
				internet::http::headers::parse_result parse_server_headers(const void* buf, size_t count)
				{
					if (!server_headers) {
						if ((server_headers = new (std::nothrow) internet::http::headers()) == NULL) {
							return internet::http::headers::PARSE_NO_MEMORY;
						}
					}

					return server_headers->parse(buf, count);
				}
			} http;
		} protocol;

		// Initialize.
		void init();

		// Reset.
		void reset();

		// Print connection.
		void print() const;

		// Append incoming data.
		bool append_in(const char* data, size_t len);

		// Append outgoing data.
		bool append_out(const char* data, size_t len);

		// Serialize.
		bool serialize(string::buffer& buf) const;
	};

	inline void connection::reset()
	{
		if (in) {
			if (in->size() > 2 * kInBufferAlloc) {
				in->free();
			} else {
				in->reset();
			}
		}

		if (out) {
			if (out->size() > 2 * kOutBufferAlloc) {
				out->free();
			} else {
				out->reset();
			}
		}

		if (protocol.http.server_headers) {
			protocol.http.server_headers->reset();
		}
	}

	inline void connection::print() const
	{
		const unsigned char* saddr = (const unsigned char*) &srcip;
		const unsigned char* daddr = (const unsigned char*) &destip;

		printf("\t[%s] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u:\n", (direction == 0) ? "OUT" : "IN", saddr[0], saddr[1], saddr[2], saddr[3], srcport, daddr[0], daddr[1], daddr[2], daddr[3], destport);
		printf("\t\tCreation: %ld\n", creation);
		printf("\t\tLast activity: %ld\n", timestamp);
		printf("\t\tUploaded: %lld\n", uploaded);
		printf("\t\tDownloaded: %lld\n", downloaded);
	}

	inline bool connection::append_in(const char* data, size_t len)
	{
		if (!in) {
			if ((in = new (std::nothrow) string::buffer(kInBufferAlloc)) == NULL) {
				return false;
			}
		}

		return in->append(data, len);
	}

	inline bool connection::append_out(const char* data, size_t len)
	{
		if (!out) {
			if ((out = new (std::nothrow) string::buffer(kOutBufferAlloc)) == NULL) {
				return false;
			}
		}

		return out->append(data, len);
	}

	inline bool connection::serialize(string::buffer& buf) const
	{
		const unsigned char* saddr = (const unsigned char*) &srcip;
		const unsigned char* daddr = (const unsigned char*) &destip;

		return buf.format("%u.%u.%u.%u:%u\t%s\t%u.%u.%u.%u:%u\t%ld\t%ld\t%lld\t%lld\n", saddr[0], saddr[1], saddr[2], saddr[3], srcport, (direction == 0) ? "->" : "<-", daddr[0], daddr[1], daddr[2], daddr[3], destport, creation, timestamp, uploaded, downloaded);
	}
}

#endif // NET_CONNECTION_H
