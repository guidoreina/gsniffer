#ifndef CONNECTION_LIST_H
#define CONNECTION_LIST_H

#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ip_address.h"

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

		// Get number of connections.
		size_t get_number_connections() const;

		// Print connections.
		void print() const;

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

		// Indexed by source port.
		ip_fragments* _M_fragments;

		connections _M_connections;

		// Connections are added to the head.
		int _M_head;
		int _M_tail;

		int _M_free_connection;

		// Allocate connection.
		connection* allocate_connection();

		// Allocate index.
		bool allocate_index(ip_fragment* fragment);

		// Allocate IP fragment.
		bool allocate_ip_fragment(ip_fragments* fragments);

		// Delete connection.
		void delete_connection(unsigned short srcport, size_t pos, size_t index);
		bool delete_connection(unsigned connidx);

		// Search IP fragment.
		ip_fragment* search(const ip_fragments* fragments, const ip_address* addr, size_t& pos);

		// Search index.
		bool search(const ip_fragment* fragment, const ip_address* srcip, unsigned short srcport, const ip_address* destip, unsigned short destport, size_t& pos) const;
};

inline connection_list::~connection_list()
{
	free();
}

inline size_t connection_list::get_number_connections() const
{
	return _M_connections.used;
}

#endif // CONNECTION_LIST_H
