#ifndef CONNECTION_LIST_H
#define CONNECTION_LIST_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "connection.h"

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
		bool add(const struct iphdr* ip_header, const struct tcphdr* tcp_header, size_t payload, time_t t, connection*& conn);

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
		static const size_t NODES_ALLOC;
		static const size_t INDICES_ALLOC;
		static const size_t IP_FRAGMENTS_ALLOC;

		struct node {
			connection conn;

			int prev;
			int next;
		};

		struct nodes {
			node* nodes;
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

		nodes _M_nodes;

		// Nodes are added to the head.
		int _M_head;
		int _M_tail;

		int _M_free_node;

		index _M_index;
		buffer _M_buf;

		// Allocate node.
		node* allocate_node();

		// Allocate index.
		bool allocate_index(ip_fragment* fragment);

		// Allocate IP fragment.
		bool allocate_ip_fragment(ip_fragments* fragments);

		// Allocate indices.
		bool allocate_indices();

		// Delete node.
		void delete_node(unsigned short srcport, size_t pos, size_t index);
		bool delete_node(unsigned idx);

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
	return _M_nodes.used;
}

#endif // CONNECTION_LIST_H
