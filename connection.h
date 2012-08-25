#ifndef CONNECTION_H
#define CONNECTION_H

#include <time.h>
#include <stdio.h>
#include <memory>
#include "ip_address.h"
#include "buffer.h"

struct connection {
	static const size_t IN_BUFFER_ALLOC;
	static const size_t OUT_BUFFER_ALLOC;

	ip_address srcip;
	ip_address destip;
	unsigned short srcport;
	unsigned short destport;

	time_t creation;
	time_t timestamp; // Time last activity.

	off_t uploaded;
	off_t downloaded;

	buffer* in;
	buffer* out;

	size_t in_offset;
	size_t out_offset;

	unsigned char state:4;
	unsigned char direction:1; // 0: Outgoing, 1: Incoming.

	unsigned char first_upload:1;
	unsigned char first_download:1;

	// Reset.
	void reset();

	// Print connection.
	void print() const;

	// Append incoming data.
	bool append_in(const char* data, size_t len);

	// Append outgoing data.
	bool append_out(const char* data, size_t len);

	// Serialize.
	bool serialize(buffer& buf) const;
};

inline void connection::reset()
{
	if (in) {
		if (in->size() > 2 * IN_BUFFER_ALLOC) {
			in->free();
		} else {
			in->reset();
		}
	}

	if (out) {
		if (out->size() > 2 * OUT_BUFFER_ALLOC) {
			out->free();
		} else {
			out->reset();
		}
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
		if ((in = new (std::nothrow) buffer(IN_BUFFER_ALLOC)) == NULL) {
			return false;
		}
	}

	return in->append(data, len);
}

inline bool connection::append_out(const char* data, size_t len)
{
	if (!out) {
		if ((out = new (std::nothrow) buffer(OUT_BUFFER_ALLOC)) == NULL) {
			return false;
		}
	}

	return out->append(data, len);
}

inline bool connection::serialize(buffer& buf) const
{
	const unsigned char* saddr = (const unsigned char*) &srcip;
	const unsigned char* daddr = (const unsigned char*) &destip;

	return buf.format("%u.%u.%u.%u:%u\t%s\t%u.%u.%u.%u:%u\t%ld\t%ld\t%lld\t%lld\n", saddr[0], saddr[1], saddr[2], saddr[3], srcport, (direction == 0) ? "->" : "<-", daddr[0], daddr[1], daddr[2], daddr[3], destport, creation, timestamp, uploaded, downloaded);
}

#endif // CONNECTION_H
