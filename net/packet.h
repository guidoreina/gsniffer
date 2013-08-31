#ifndef NET_PACKET_H
#define NET_PACKET_H

namespace net {
	enum {
		kOutgoingPacket,
		kIncomingPacket
	};

	struct packet {
		const unsigned char* payload;
		size_t len;

		unsigned char direction;
	};
}

#endif // NET_PACKET_H
