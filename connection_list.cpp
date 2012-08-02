#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "connection_list.h"

const time_t connection_list::EXPIRATION_TIMEOUT = 2 * 60 * 60;
const size_t connection_list::CONNECTIONS_ALLOC = 1024;
const size_t connection_list::INDICES_ALLOC = 128;
const size_t connection_list::IP_FRAGMENTS_ALLOC = 32;

connection_list::connection_list() : _M_buf(64 * 1024)
{
	_M_fragments = NULL;

	_M_connections.connections = NULL;
	_M_connections.size = 0;
	_M_connections.used = 0;

	_M_head = -1;
	_M_tail = -1;

	_M_free_connection = -1;

	_M_index.indices = NULL;
	_M_index.size = 0;
	_M_index.used = 0;
}

void connection_list::free()
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

	if (_M_connections.connections) {
		::free(_M_connections.connections);
		_M_connections.connections = NULL;
	}

	_M_connections.size = 0;
	_M_connections.used = 0;

	_M_head = -1;
	_M_tail = -1;

	_M_free_connection = -1;

	if (_M_index.indices) {
		::free(_M_index.indices);
		_M_index.indices = NULL;
	}

	_M_index.size = 0;
	_M_index.used = 0;
}

bool connection_list::create()
{
	if ((_M_fragments = (struct ip_fragments*) calloc(64 * 1024, sizeof(struct ip_fragments))) == NULL) {
		return false;
	}

	return true;
}

bool connection_list::add(const struct iphdr* ip_header, const struct tcphdr* tcp_header, size_t payload, time_t t, bool& first_payload)
{
	ip_address addresses[2];
	unsigned short ports[2];
	size_t transferred[2];
	unsigned char direction;

	unsigned short srcport = ntohs(tcp_header->source);
	unsigned short destport = ntohs(tcp_header->dest);

	if (srcport >= destport) {
		addresses[0].ipv4 = ip_header->saddr;
		addresses[1].ipv4 = ip_header->daddr;

		ports[0] = srcport;
		ports[1] = destport;

		transferred[0] = payload;
		transferred[1] = 0;

		direction = 0;
	} else {
		addresses[0].ipv4 = ip_header->daddr;
		addresses[1].ipv4 = ip_header->saddr;

		ports[0] = destport;
		ports[1] = srcport;

		transferred[0] = 0;
		transferred[1] = payload;

		direction = 1;
	}

	ip_fragments* fragments = &_M_fragments[ports[0]];

	// Search IP fragment.
	ip_fragment* fragment;
	size_t pos;
	if ((fragment = search(fragments, addresses[0], pos)) == NULL) {
		// If not a SYN + ACK...
		if ((!tcp_header->syn) || (!tcp_header->ack)) {
			// Ignore packet.
			first_payload = false;
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
			first_payload = false;
			return true;
		}

		connection* conn;
		if ((!allocate_index(fragment)) || ((conn = allocate_connection()) == NULL)) {
			return false;
		}

		if (index < fragment->used) {
			memmove(&fragment->indices[index + 1], &fragment->indices[index], (fragment->used - index) * sizeof(unsigned));
		}

		fragment->indices[index] = _M_head;

		// Initialize connection.
		conn->srcip = addresses[0];
		conn->destip = addresses[1];

		conn->srcport = ports[0];
		conn->destport = ports[1];

		conn->creation = t;
		conn->timestamp = t;

		conn->uploaded = transferred[0];
		conn->downloaded = transferred[1];

		conn->state = 0;
		conn->direction = !direction; // Invert direction (this is the second packet).

		fragment->used++;

		first_payload = (payload > 0);

		return true;
	}

	// If the connection has to be deleted...
	if ((tcp_header->rst) || (tcp_header->fin)) {
		delete_connection(ports[0], pos, index);
		first_payload = false;

		return true;
	}

	connection* conn = &_M_connections.connections[fragment->indices[index]];

	conn->timestamp = t;

	first_payload = (payload > 0) && ((conn->uploaded == 0) && (conn->downloaded == 0));

	conn->uploaded += transferred[0];
	conn->downloaded += transferred[1];

	return true;
}

void connection_list::delete_expired(time_t now)
{
	connection* connections = _M_connections.connections;

	while (_M_tail != -1) {
		connection* conn = &connections[_M_tail];

		if (conn->timestamp + EXPIRATION_TIMEOUT > now) {
			return;
		}

#if DEBUG
		const unsigned char* srcip = (const unsigned char*) &conn->srcip;
		const unsigned char* destip = (const unsigned char*) &conn->destip;

		printf("Deleting expired connection: %u.%u.%u.%u:%u %s %u.%u.%u.%u:%u, timestamp: %ld.\n", srcip[0], srcip[1], srcip[2], srcip[3], conn->srcport, (conn->direction == 0) ? "->" : "<-", destip[0], destip[1], destip[2], destip[3], conn->destport, conn->timestamp);
#endif // DEBUG

		delete_connection(_M_tail);
	}
}

bool connection_list::save(const char* filename, bool ordered)
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

void connection_list::print() const
{
	printf("# of connections: %u:\n", _M_connections.used);

	const connection* connections = _M_connections.connections;

	int i = _M_head;
	while (i != -1) {
		const connection* conn = &connections[i];

		const unsigned char* saddr = (const unsigned char*) &conn->srcip;
		const unsigned char* daddr = (const unsigned char*) &conn->destip;

		printf("\t[%s] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u:\n", (conn->direction == 0) ? "OUT" : "IN", saddr[0], saddr[1], saddr[2], saddr[3], conn->srcport, daddr[0], daddr[1], daddr[2], daddr[3], conn->destport);
		printf("\t\tCreation: %ld\n", conn->creation);
		printf("\t\tLast activity: %ld\n", conn->timestamp);
		printf("\t\tUploaded: %lld\n", conn->uploaded);
		printf("\t\tDownloaded: %lld\n", conn->downloaded);

		i = conn->next;
	}
}

bool connection_list::serialize(bool ordered, buffer& buf)
{
	const connection* connections = _M_connections.connections;

	if (!ordered) {
		int i = _M_head;
		while (i != -1) {
			if (!connections[i].serialize(buf)) {
				return false;
			}

			i = connections[i].next;
		}
	} else {
		if (!build_index()) {
			return false;
		}

		const unsigned* indices = _M_index.indices;
		size_t used = _M_index.used;

		for (size_t i = 0; i < used; i++) {
			if (!connections[indices[i]].serialize(buf)) {
				return false;
			}
		}
	}

	return true;
}

connection_list::connection* connection_list::allocate_connection()
{
	// If we have to allocate a new connection...
	if (_M_free_connection == -1) {
		size_t size = (_M_connections.size == 0) ? CONNECTIONS_ALLOC : _M_connections.size * 2;

		connection* connections;
		if ((connections = (struct connection*) realloc(_M_connections.connections, size * sizeof(struct connection))) == NULL) {
			return NULL;
		}

		size_t i;
		for (i = _M_connections.size; i < size - 1; i++) {
			connections[i].next = i + 1;
		}

		connections[i].next = -1;

		_M_free_connection = _M_connections.size;

		_M_connections.connections = connections;
		_M_connections.size = size;
	}

	connection* conn = &_M_connections.connections[_M_free_connection];

	// Save next free connection.
	int next = conn->next;

	conn->prev = -1;
	conn->next = _M_head;

	// If this is not the first connection...
	if (_M_head != -1) {
		_M_connections.connections[_M_head].prev = _M_free_connection;
	} else {
		_M_tail = _M_free_connection;
	}

	_M_head = _M_free_connection;
	_M_free_connection = next;

	_M_connections.used++;

#if DEBUG
	printf("# of connections: %u.\n", _M_connections.used);
#endif

	return conn;
}

bool connection_list::allocate_index(ip_fragment* fragment)
{
	if (fragment->used == fragment->size) {
		size_t size = (fragment->size == 0) ? INDICES_ALLOC : fragment->size * 2;

		unsigned* indices;
		if ((indices = (unsigned*) realloc(fragment->indices, size * sizeof(unsigned))) == NULL) {
			return false;
		}

		fragment->indices = indices;
		fragment->size = size;
	}

	return true;
}

bool connection_list::allocate_ip_fragment(ip_fragments* fragments)
{
	if (fragments->used == fragments->size) {
		size_t size = (fragments->size == 0) ? IP_FRAGMENTS_ALLOC : fragments->size * 2;

		ip_fragment* f;
		if ((f = (struct ip_fragment*) realloc(fragments->fragments, size * sizeof(struct ip_fragment))) == NULL) {
			return false;
		}

		fragments->fragments = f;
		fragments->size = size;
	}

	return true;
}

bool connection_list::allocate_indices()
{
	if (_M_index.size < _M_connections.used) {
		unsigned* indices;
		if ((indices = (unsigned*) realloc(_M_index.indices, _M_connections.used * sizeof(unsigned))) == NULL) {
			return false;
		}

		_M_index.indices = indices;
		_M_index.size = _M_connections.used;
	}

	return true;
}

void connection_list::delete_connection(unsigned short srcport, size_t pos, size_t index)
{
	ip_fragments* fragments = &_M_fragments[srcport];
	ip_fragment* fragment = &fragments->fragments[pos];
	unsigned connidx = fragment->indices[index];

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

	// Add connection to the free list.
	connection* conn = &_M_connections.connections[connidx];
	if (conn->prev != -1) {
		_M_connections.connections[conn->prev].next = conn->next;
	}

	if (conn->next != -1) {
		_M_connections.connections[conn->next].prev = conn->prev;
	}

	if ((int) connidx == _M_head) {
		_M_head = conn->next;
	}

	if ((int) connidx == _M_tail) {
		_M_tail = conn->prev;
	}

	conn->next = _M_free_connection;
	_M_free_connection = connidx;

	_M_connections.used--;

#if DEBUG
	printf("# of connections: %u.\n", _M_connections.used);
#endif
}

bool connection_list::delete_connection(unsigned connidx)
{
	connection* conn = &_M_connections.connections[connidx];

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

	delete_connection(conn->srcport, pos, index);

	return true;
}

connection_list::ip_fragment* connection_list::search(const ip_fragments* fragments, const ip_address& addr, size_t& pos)
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

bool connection_list::search(const ip_fragment* fragment, const ip_address& srcip, unsigned short srcport, const ip_address& destip, unsigned short destport, size_t& pos) const
{
	const connection* connections = _M_connections.connections;
	const unsigned* indices = fragment->indices;

	int i = 0;
	int j = fragment->used - 1;

	while (i <= j) {
		int pivot = (i + j) / 2;
		const connection* conn = &connections[indices[pivot]];

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

bool connection_list::build_index()
{
	if (!allocate_indices()) {
		return false;
	}

	const connection* connections = _M_connections.connections;
	unsigned* indices = _M_index.indices;

	_M_index.used = 0;

	int idx = _M_head;
	while (idx != -1) {
		const connection* conn = &connections[idx];

		size_t pos;
		search(conn->srcip, conn->destip, pos);

		if (pos < _M_index.used) {
			memmove(&indices[pos + 1], &indices[pos], (_M_index.used - pos) * sizeof(unsigned));
		}

		indices[pos] = idx;

		_M_index.used++;

		idx = conn->next;
	}

	return true;
}

void connection_list::search(const ip_address& srcip, const ip_address& destip, size_t& pos) const
{
	const connection* connections = _M_connections.connections;
	const unsigned* indices = _M_index.indices;

	int i = 0;
	int j = _M_index.used - 1;

	while (i <= j) {
		int pivot = (i + j) / 2;
		const connection* conn = &connections[indices[pivot]];

		int ret = ip_address::compare(srcip, conn->srcip);
		if (ret < 0) {
			j = pivot - 1;
		} else if (ret == 0) {
			ret = ip_address::compare(destip, conn->destip);
			if (ret < 0) {
				j = pivot - 1;
			} else if (ret == 0) {
				while (++pivot < (int) _M_index.used) {
					conn = &connections[indices[pivot]];
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
