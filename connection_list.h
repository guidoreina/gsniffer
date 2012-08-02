#ifndef CONNECTION_LIST_H
#define CONNECTION_LIST_H

#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ip_address.h"
#include "buffer.h"

class connection_list {
	public:
		static const time_t EXPIRATION_TIMEOUT;

		// Constructor.
		connection_list();

		// Destructor.
		~connection_list();

		// Free object.
		void free();

		// Create.
		bool create();

		// Add packet.
		bool add(const struct iphdr* ip_header, const struct tcphdr* tcp_header, size_t payload, time_t t, bool& first_payload);

		// Delete expired connections.
		void delete_expired(time_t now);

		// Save.
		bool save(const char* filename, bool ordered);

		// Get number of connections.
		size_t get_number_connections() const;

		// Print connections.
		void print() const;

		// Serialize.
		bool serialize(bool ordered, buffer& buf);

	protected:
		static const size_t CONNECTIONS_ALLOC;
		static const size_t INDICES_ALLOC;
		static const size_t IP_FRAGMENTS_ALLOC;

		struct connection {
			ip_address srcip;
			ip_address destip;
			unsigned short srcport;
			unsigned short destport;

			time_t creation;
			time_t timestamp; // Time last activity.

			off_t uploaded;
			off_t downloaded;

			unsigned char state:4;
			unsigned char direction:1; // 0: Outgoing, 1: Incoming.

			int prev;
			int next;

			bool serialize(buffer& buf) const;
		};

		struct connections {
			connection* connections;
			size_t size;
			size_t used;
		};

		struct ip_fragment {
			unsigned char data;

			unsigned* indices;
			size_t size;
			size_t used;
		};

		struct ip_fragments {
			ip_fragment* fragments;
			unsigned char size;
			unsigned char used;
		};

		struct index {
			unsigned* indices;
			size_t size;
			size_t used;
		};

		// Indexed by source port.
		ip_fragments* _M_fragments;

		connections _M_connections;

		// Connections are added to the head.
		int _M_head;
		int _M_tail;

		int _M_free_connection;

		index _M_index;
		buffer _M_buf;

		// Allocate connection.
		connection* allocate_connection();

		// Allocate index.
		bool allocate_index(ip_fragment* fragment);

		// Allocate IP fragment.
		bool allocate_ip_fragment(ip_fragments* fragments);

		// Allocate indices.
		bool allocate_indices();

		// Delete connection.
		void delete_connection(unsigned short srcport, size_t pos, size_t index);
		bool delete_connection(unsigned connidx);

		// Search IP fragment.
		ip_fragment* search(const ip_fragments* fragments, const ip_address& addr, size_t& pos);

		// Search index.
		bool search(const ip_fragment* fragment, const ip_address& srcip, unsigned short srcport, const ip_address& destip, unsigned short destport, size_t& pos) const;

		// Build index.
		bool build_index();

		// Search index.
		void search(const ip_address& srcip, const ip_address& destip, size_t& pos) const;
};

inline connection_list::~connection_list()
{
	free();
}

inline size_t connection_list::get_number_connections() const
{
	return _M_connections.used;
}

inline bool connection_list::connection::serialize(buffer& buf) const
{
	const unsigned char* src = (const unsigned char*) &srcip;
	const unsigned char* dest = (const unsigned char*) &destip;

	return buf.format("%u.%u.%u.%u:%u\t%s\t%u.%u.%u.%u:%u\t%ld\t%ld\t%lld\t%lld\n", src[0], src[1], src[2], src[3], srcport, (direction == 0) ? "->" : "<-", dest[0], dest[1], dest[2], dest[3], destport, creation, timestamp, uploaded, downloaded);
}

#endif // CONNECTION_LIST_H
