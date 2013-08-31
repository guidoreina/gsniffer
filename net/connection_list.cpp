#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "net/connection_list.h"
#include "net/packet.h"

net::connection_list::connection_list() : _M_buf(64 * 1024)
{
	_M_fragments = NULL;

	_M_nodes.nodes = NULL;
	_M_nodes.size = 0;
	_M_nodes.used = 0;

	_M_head = -1;
	_M_tail = -1;

	_M_free_node = -1;

	_M_index.indices = NULL;
	_M_index.size = 0;
	_M_index.used = 0;
}

void net::connection_list::free()
{
	if (_M_fragments) {
		for (unsigned i = 0; i < 64 * 1024; i++) {
			ip_fragments* fragments = &_M_fragments[i];
			if (fragments->fragments) {
				for (size_t j = fragments->used; j > 0; j--) {
					unsigned* indices;
					if ((indices = fragments->fragments[j - 1].indices) != NULL) {
						::free(indices);
					}
				}

				::free(fragments->fragments);
			}
		}

		::free(_M_fragments);
		_M_fragments = NULL;
	}

	if (_M_nodes.nodes) {
		for (size_t i = 0; i < _M_nodes.size; i++) {
			if (_M_nodes.nodes[i].conn.in) {
				delete _M_nodes.nodes[i].conn.in;
			}

			if (_M_nodes.nodes[i].conn.out) {
				delete _M_nodes.nodes[i].conn.out;
			}

			if (_M_nodes.nodes[i].conn.protocol.http.server_headers) {
				delete _M_nodes.nodes[i].conn.protocol.http.server_headers;
			}
		}

		::free(_M_nodes.nodes);
		_M_nodes.nodes = NULL;
	}

	_M_nodes.size = 0;
	_M_nodes.used = 0;

	_M_head = -1;
	_M_tail = -1;

	_M_free_node = -1;

	if (_M_index.indices) {
		::free(_M_index.indices);
		_M_index.indices = NULL;
	}

	_M_index.size = 0;
	_M_index.used = 0;
}

bool net::connection_list::create()
{
	if ((_M_fragments = (struct ip_fragments*) calloc(64 * 1024, sizeof(struct ip_fragments))) == NULL) {
		return false;
	}

	return true;
}

bool net::connection_list::add(const struct iphdr* ip_header, const struct tcphdr* tcp_header, size_t payload, time_t t, connection*& conn, unsigned char& direction)
{
	ip_address addresses[2];
	unsigned short ports[2];
	size_t transferred[2];

	unsigned short srcport = ntohs(tcp_header->source);
	unsigned short destport = ntohs(tcp_header->dest);

	if (srcport >= destport) {
		addresses[0].ipv4 = ip_header->saddr;
		addresses[1].ipv4 = ip_header->daddr;

		ports[0] = srcport;
		ports[1] = destport;

		transferred[0] = payload;
		transferred[1] = 0;

		direction = kOutgoingPacket;
	} else {
		addresses[0].ipv4 = ip_header->daddr;
		addresses[1].ipv4 = ip_header->saddr;

		ports[0] = destport;
		ports[1] = srcport;

		transferred[0] = 0;
		transferred[1] = payload;

		direction = kIncomingPacket;
	}

	ip_fragments* fragments = &_M_fragments[ports[0]];

	// Search IP fragment.
	ip_fragment* fragment;
	size_t pos;
	if ((fragment = search(fragments, addresses[0], pos)) == NULL) {
		// If not a SYN + ACK...
		if ((!tcp_header->syn) || (!tcp_header->ack)) {
			// Ignore packet.
			conn = NULL;
			return true;
		}

		if (!allocate_ip_fragment(fragments)) {
			return false;
		}

		if (pos < fragments->used) {
			memmove(&fragments->fragments[pos + 1], &fragments->fragments[pos], (fragments->used - pos) * sizeof(struct ip_fragment));
		}

		fragment = &fragments->fragments[pos];
		fragment->data = ((const unsigned char*) addresses)[sizeof(ip_address) - 1];

		fragment->indices = NULL;
		fragment->size = 0;
		fragment->used = 0;

		fragments->used++;
	}

	// Search index in IP fragment.
	size_t index;
	if (!search(fragment, addresses[0], ports[0], addresses[1], ports[1], index)) {
		// If not a SYN + ACK...
		if ((!tcp_header->syn) || (!tcp_header->ack)) {
			// Ignore packet.
			conn = NULL;
			return true;
		}

		node* n;
		if ((!allocate_index(fragment)) || ((n = allocate_node()) == NULL)) {
			return false;
		}

		if (index < fragment->used) {
			memmove(&fragment->indices[index + 1], &fragment->indices[index], (fragment->used - index) * sizeof(unsigned));
		}

		fragment->indices[index] = _M_head;

		// Initialize connection.
		conn = &n->conn;

		conn->init();

		conn->srcip = addresses[0];
		conn->destip = addresses[1];

		conn->srcport = ports[0];
		conn->destport = ports[1];

		conn->creation = t;
		conn->timestamp = t;

		conn->uploaded = transferred[0];
		conn->downloaded = transferred[1];

		conn->direction = !direction; // Invert direction (this is the second packet).

		fragment->used++;

		return true;
	}

	// If the connection has to be deleted...
	if ((tcp_header->rst) || (tcp_header->fin)) {
		delete_node(ports[0], pos, index);

		conn = NULL;
		return true;
	}

	conn = &_M_nodes.nodes[fragment->indices[index]].conn;

	conn->timestamp = t;

	conn->uploaded += transferred[0];
	conn->downloaded += transferred[1];

	return true;
}

void net::connection_list::delete_expired(time_t now)
{
	node* nodes = _M_nodes.nodes;

	while (_M_tail != -1) {
		connection* conn = &nodes[_M_tail].conn;

		if (conn->timestamp + kExpirationTimeout > now) {
			return;
		}

#if DEBUG
		const unsigned char* srcip = (const unsigned char*) &conn->srcip;
		const unsigned char* destip = (const unsigned char*) &conn->destip;

		printf("Deleting expired connection: %u.%u.%u.%u:%u %s %u.%u.%u.%u:%u, timestamp: %ld.\n", srcip[0], srcip[1], srcip[2], srcip[3], conn->srcport, (conn->direction == 0) ? "->" : "<-", destip[0], destip[1], destip[2], destip[3], conn->destport, conn->timestamp);
#endif // DEBUG

		delete_node(_M_tail);
	}
}

bool net::connection_list::save(const char* filename, bool ordered)
{
	char tmpfilename[PATH_MAX + 1];
	snprintf(tmpfilename, sizeof(tmpfilename), "%s.tmp", filename);

	int fd;
	if ((fd = open(tmpfilename, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
		return false;
	}

	_M_buf.reset();

	if (!serialize(ordered, _M_buf)) {
		close(fd);
		unlink(tmpfilename);

		return false;
	}

	size_t written = 0;
	while (written < _M_buf.count()) {
		ssize_t ret;
		if ((ret = write(fd, _M_buf.data() + written, _M_buf.count() - written)) < 0) {
			if (errno != EINTR) {
				close(fd);
				unlink(tmpfilename);

				return false;
			}
		} else if (ret > 0) {
			written += ret;
		}
	}

	close(fd);

	return (rename(tmpfilename, filename) == 0);
}

void net::connection_list::print() const
{
	printf("# of connections: %u:\n", _M_nodes.used);

	const node* nodes = _M_nodes.nodes;

	int i = _M_head;
	while (i != -1) {
		nodes[i].conn.print();

		i = nodes[i].next;
	}
}

bool net::connection_list::serialize(bool ordered, string::buffer& buf)
{
	const node* nodes = _M_nodes.nodes;

	if (!ordered) {
		int i = _M_head;
		while (i != -1) {
			if (!nodes[i].conn.serialize(buf)) {
				return false;
			}

			i = nodes[i].next;
		}
	} else {
		if (!build_index()) {
			return false;
		}

		const unsigned* indices = _M_index.indices;
		size_t used = _M_index.used;

		for (size_t i = 0; i < used; i++) {
			if (!nodes[indices[i]].conn.serialize(buf)) {
				return false;
			}
		}
	}

	return true;
}

net::connection_list::node* net::connection_list::allocate_node()
{
	// If we have to allocate a new node...
	if (_M_free_node == -1) {
		size_t size = (_M_nodes.size == 0) ? kNodesAlloc : _M_nodes.size * 2;

		node* nodes;
		if ((nodes = (struct node*) realloc(_M_nodes.nodes, size * sizeof(struct node))) == NULL) {
			return NULL;
		}

		size_t i;
		for (i = _M_nodes.size; i < size - 1; i++) {
			nodes[i].conn.in = NULL;
			nodes[i].conn.out = NULL;
			nodes[i].conn.protocol.http.server_headers = NULL;

			nodes[i].next = i + 1;
		}

		nodes[i].conn.in = NULL;
		nodes[i].conn.out = NULL;
		nodes[i].conn.protocol.http.server_headers = NULL;

		nodes[i].next = -1;

		_M_free_node = _M_nodes.size;

		_M_nodes.nodes = nodes;
		_M_nodes.size = size;
	}

	node* n = &_M_nodes.nodes[_M_free_node];

	// Save next free node.
	int next = n->next;

	n->prev = -1;
	n->next = _M_head;

	// If this is not the first node...
	if (_M_head != -1) {
		_M_nodes.nodes[_M_head].prev = _M_free_node;
	} else {
		_M_tail = _M_free_node;
	}

	_M_head = _M_free_node;
	_M_free_node = next;

	_M_nodes.used++;

#if DEBUG
	printf("# of connections: %u.\n", _M_nodes.used);
#endif

	return n;
}

bool net::connection_list::allocate_index(ip_fragment* fragment)
{
	if (fragment->used == fragment->size) {
		size_t size = (fragment->size == 0) ? kIndicesAlloc : fragment->size * 2;

		unsigned* indices;
		if ((indices = (unsigned*) realloc(fragment->indices, size * sizeof(unsigned))) == NULL) {
			return false;
		}

		fragment->indices = indices;
		fragment->size = size;
	}

	return true;
}

bool net::connection_list::allocate_ip_fragment(ip_fragments* fragments)
{
	if (fragments->used == fragments->size) {
		size_t size = (fragments->size == 0) ? kIpFragmentsAlloc : fragments->size * 2;

		ip_fragment* f;
		if ((f = (struct ip_fragment*) realloc(fragments->fragments, size * sizeof(struct ip_fragment))) == NULL) {
			return false;
		}

		fragments->fragments = f;
		fragments->size = size;
	}

	return true;
}

bool net::connection_list::allocate_indices()
{
	if (_M_index.size < _M_nodes.used) {
		unsigned* indices;
		if ((indices = (unsigned*) realloc(_M_index.indices, _M_nodes.used * sizeof(unsigned))) == NULL) {
			return false;
		}

		_M_index.indices = indices;
		_M_index.size = _M_nodes.used;
	}

	return true;
}

void net::connection_list::delete_node(unsigned short srcport, size_t pos, size_t index)
{
	ip_fragments* fragments = &_M_fragments[srcport];
	ip_fragment* fragment = &fragments->fragments[pos];
	unsigned idx = fragment->indices[index];

	// Remove index.
	fragment->used--;

	// If there are more indices...
	if (fragment->used > 0) {
		if (index < fragment->used) {
			memmove(&fragment->indices[index], &fragment->indices[index + 1], (fragment->used - index) * sizeof(unsigned));
		}
	} else {
		// Delete IP fragment.
		::free(fragment->indices);

		fragments->used--;

		// If there are more IP fragments...
		if (fragments->used > 0) {
			if (pos < fragments->used) {
				memmove(&fragments->fragments[pos], &fragments->fragments[pos + 1], (fragments->used - pos) * sizeof(struct ip_fragment));
			}
		} else {
			// Remove fragments.
			::free(fragments->fragments);
			fragments->fragments = NULL;

			fragments->size = 0;
		}
	}

	// Add node to the free list.
	node* n = &_M_nodes.nodes[idx];
	if (n->prev != -1) {
		_M_nodes.nodes[n->prev].next = n->next;
	}

	if (n->next != -1) {
		_M_nodes.nodes[n->next].prev = n->prev;
	}

	if ((int) idx == _M_head) {
		_M_head = n->next;
	}

	if ((int) idx == _M_tail) {
		_M_tail = n->prev;
	}

	n->conn.reset();

	n->next = _M_free_node;
	_M_free_node = idx;

	_M_nodes.used--;

#if DEBUG
	printf("# of connections: %u.\n", _M_nodes.used);
#endif
}

bool net::connection_list::delete_node(unsigned idx)
{
	connection* conn = &_M_nodes.nodes[idx].conn;

	// Search IP fragment.
	ip_fragment* fragment;
	size_t pos;
	if ((fragment = search(&_M_fragments[conn->srcport], conn->srcip, pos)) == NULL) {
		return false;
	}

	// Search index in IP fragment.
	size_t index;
	if (!search(fragment, conn->srcip, conn->srcport, conn->destip, conn->destport, index)) {
		return false;
	}

	delete_node(conn->srcport, pos, index);

	return true;
}

net::connection_list::ip_fragment* net::connection_list::search(const ip_fragments* fragments, const ip_address& addr, size_t& pos)
{
	ip_fragment* f = fragments->fragments;

	int i = 0;
	int j = fragments->used - 1;

	unsigned char data = ((const unsigned char*) &addr)[sizeof(ip_address) - 1];

	while (i <= j) {
		int pivot = (i + j) / 2;

		if (data < f[pivot].data) {
			j = pivot - 1;
		} else if (data == f[pivot].data) {
			pos = pivot;
			return &f[pivot];
		} else {
			i = pivot + 1;
		}
	}

	pos = i;

	return NULL;
}

bool net::connection_list::search(const ip_fragment* fragment, const ip_address& srcip, unsigned short srcport, const ip_address& destip, unsigned short destport, size_t& pos) const
{
	const node* nodes = _M_nodes.nodes;
	const unsigned* indices = fragment->indices;

	int i = 0;
	int j = fragment->used - 1;

	while (i <= j) {
		int pivot = (i + j) / 2;
		const connection* conn = &nodes[indices[pivot]].conn;

		if (srcip < conn->srcip) {
			j = pivot - 1;
		} else if (srcip == conn->srcip) {
			if (srcport < conn->srcport) {
				j = pivot - 1;
			} else if (srcport == conn->srcport) {
				if (destip < conn->destip) {
					j = pivot - 1;
				} else if (destip == conn->destip) {
					if (destport < conn->destport) {
						j = pivot - 1;
					} else if (destport == conn->destport) {
						pos = pivot;
						return true;
					} else {
						i = pivot + 1;
					}
				} else {
					i = pivot + 1;
				}
			} else {
				i = pivot + 1;
			}
		} else {
			i = pivot + 1;
		}
	}

	pos = i;

	return false;
}

bool net::connection_list::build_index()
{
	if (!allocate_indices()) {
		return false;
	}

	const node* nodes = _M_nodes.nodes;
	unsigned* indices = _M_index.indices;

	_M_index.used = 0;

	int idx = _M_head;
	while (idx != -1) {
		const node* n = &nodes[idx];

		size_t pos;
		search(n->conn.srcip, n->conn.destip, pos);

		if (pos < _M_index.used) {
			memmove(&indices[pos + 1], &indices[pos], (_M_index.used - pos) * sizeof(unsigned));
		}

		indices[pos] = idx;

		_M_index.used++;

		idx = n->next;
	}

	return true;
}

void net::connection_list::search(const ip_address& srcip, const ip_address& destip, size_t& pos) const
{
	const node* nodes = _M_nodes.nodes;
	const unsigned* indices = _M_index.indices;

	int i = 0;
	int j = _M_index.used - 1;

	while (i <= j) {
		int pivot = (i + j) / 2;
		const connection* conn = &nodes[indices[pivot]].conn;

		int ret = ip_address::compare(srcip, conn->srcip);
		if (ret < 0) {
			j = pivot - 1;
		} else if (ret == 0) {
			ret = ip_address::compare(destip, conn->destip);
			if (ret < 0) {
				j = pivot - 1;
			} else if (ret == 0) {
				while (++pivot < (int) _M_index.used) {
					conn = &nodes[indices[pivot]].conn;
					if ((srcip != conn->srcip) || (destip != conn->destip)) {
						break;
					}
				}

				pos = pivot;
				return;
			} else {
				i = pivot + 1;
			}
		} else {
			i = pivot + 1;
		}
	}

	pos = i;
}
