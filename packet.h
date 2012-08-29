#ifndef PACKET_H
#define PACKET_H

#define OUTGOING_PACKET 0
#define INCOMING_PACKET 1

typedef struct {
	const unsigned char* payload;
	size_t len;

	unsigned char direction;
} packet;

#endif // PACKET_H
