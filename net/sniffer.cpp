#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "net/sniffer.h"

const char* net::sniffer::kConnectionsFilename = "connections.txt";
const char* net::sniffer::kPipeFilename = "/tmp/gsniffer.pipe";

net::sniffer::sniffer()
{
	*_M_interface = 0;
	_M_fd = -1;

	_M_buf = MAP_FAILED;
	_M_size = 0;

	_M_frames = NULL;
	_M_number_frames = 0;

	_M_idx = 0;

	_M_pipe = -1;

	_M_running = false;

	_M_handle_alarm = false;
}

net::sniffer::~sniffer()
{
	if (_M_buf != MAP_FAILED) {
		munmap(_M_buf, _M_size);
	}

	if (_M_fd != -1) {
		close(_M_fd);
	}

	if (_M_frames) {
		free(_M_frames);
	}

	if (_M_pipe != -1) {
		close(_M_pipe);
	}

	unlink(kPipeFilename);
}

bool net::sniffer::create(const char* interface, const char* dir, size_t size)
{
	// Sanity check.
	if ((size < kMinSize) || (size > kMaxSize)) {
		return false;
	}

	size_t len;
	if ((len = strlen(interface)) >= sizeof(_M_interface)) {
		return false;
	}

	// Create HTTP logger.
	if (!_M_http_logger.create(dir)) {
		return false;
	}

	// Create named pipe.
	umask(0);
	if ((mkfifo(kPipeFilename, 0666) < 0) && (errno != EEXIST)) {
		return false;
	}

	// Open named pipe.
	if ((_M_pipe = open(kPipeFilename, O_RDWR)) < 0) {
		return false;
	}

	// Save interface.
	memcpy(_M_interface, interface, len + 1);

	// Create socket.
	if ((_M_fd = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0) {
		return false;
	}

	// Get interface index.
	struct ifreq ifr;
	memcpy(ifr.ifr_name, interface, len + 1);

	if (ioctl(_M_fd, SIOCGIFINDEX, &ifr) < 0) {
		return false;
	}

	// Bind.
	struct sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifr.ifr_ifindex;
	addr.sll_pkttype = PACKET_HOST | PACKET_OUTGOING;
	if (bind(_M_fd, (const struct sockaddr*) &addr, sizeof(struct sockaddr_ll)) < 0) {
		return false;
	}

	// Calculate frame size.
	size_t frame_size = TPACKET_ALIGN(TPACKET_HDRLEN) + TPACKET_ALIGN(ETH_DATA_LEN);
	size_t n;
	for (n = 8; n < frame_size; n *= 2);
	frame_size = n;

	// Calculate block size.
	size_t block_size = getpagesize();
	for (; block_size < frame_size; block_size *= 2);

	// Calculate number of blocks and number of frames.
	size_t block_count = size / block_size;
	_M_size = block_count * block_size;
	_M_number_frames = _M_size / frame_size;

	struct tpacket_req req;
	req.tp_block_size = block_size;
	req.tp_block_nr = block_count;
	req.tp_frame_size = frame_size;
	req.tp_frame_nr = _M_number_frames;

	// Setup PACKET_MMAP.
	if (setsockopt(_M_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(struct tpacket_req)) < 0) {
		return false;
	}

	if ((_M_buf = mmap(NULL, _M_size, PROT_READ | PROT_WRITE, MAP_SHARED, _M_fd, 0)) == MAP_FAILED) {
		return false;
	}

	if ((_M_frames = (unsigned char**) malloc(_M_number_frames * sizeof(unsigned char*))) == NULL) {
		return false;
	}

	for (size_t i = 0; i < _M_number_frames; i++) {
		_M_frames[i] = (unsigned char*) _M_buf + (i * frame_size);
	}

	return _M_connections.create();
}

void net::sniffer::start()
{
	_M_running = true;

	struct tpacket_hdr* hdr = (struct tpacket_hdr*) _M_frames[_M_idx];

	struct pollfd fds[2];
	fds[0].fd = _M_fd;
	fds[0].events = POLLIN;

	fds[1].fd = _M_pipe;
	fds[1].events = POLLIN;

	do {
		// If there is a new frame...
		while (hdr->tp_status != TP_STATUS_KERNEL) {
			// IP protocol?
			const struct sockaddr_ll* addr = (const struct sockaddr_ll*) ((const unsigned char*) hdr + TPACKET_ALIGN(sizeof(struct tpacket_hdr)));
			if (addr->sll_protocol == ntohs(ETH_P_IP)) {
				if (!process_ip_packet((unsigned char*) hdr + hdr->tp_net, hdr->tp_len, hdr->tp_sec)) {
					// Not enough memory.
					_M_running = false;
					return;
				}
			}

			// Mark frame as free.
			hdr->tp_status = TP_STATUS_KERNEL;

			_M_idx = (_M_idx == _M_number_frames - 1) ? 0 : _M_idx + 1;
			hdr = (struct tpacket_hdr*) _M_frames[_M_idx];
		}

		if (_M_handle_alarm) {
			_M_connections.delete_expired(time(NULL));
			_M_handle_alarm = false;
		}

		do {
			fds[0].revents = 0;
			fds[1].revents = 0;

			poll(fds, 2, -1);

			// If we have received data from the pipe...
			if (fds[1].revents & POLLIN) {
				char c;
				ssize_t ret;
				if ((ret = read(_M_pipe, &c, 1)) == 0) {
					close(_M_pipe);

					if ((_M_pipe = open(kPipeFilename, O_RDWR)) < 0) {
						_M_running = false;
					}
				} else if (ret == 1) {
					if (c == 1) {
						if (!_M_connections.save(kConnectionsFilename, true)) {
							_M_running = false;
						}
					}
				}
			}
		} while ((_M_running) && (fds[0].revents == 0));
	} while (_M_running);

#if DEBUG
	struct tpacket_stats stats;
	socklen_t optlen = sizeof(struct tpacket_stats);
	if (getsockopt(_M_fd, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen) == 0) {
		printf("Received %u packets, dropped %u.\n", stats.tp_packets, stats.tp_drops);
	}
#endif // DEBUG
}

bool net::sniffer::process_ip_packet(const unsigned char* pkt, size_t len, unsigned t)
{
	if (len < sizeof(struct iphdr)) {
		return true;
	}

	const struct iphdr* ip_header = (const struct iphdr*) pkt;
	size_t iphdrlen = ip_header->ihl * 4;
	if (len < iphdrlen) {
		return true;
	}

#if DEBUG
	const unsigned char* saddr = (const unsigned char*) &ip_header->saddr;
	const unsigned char* daddr = (const unsigned char*) &ip_header->daddr;
#endif // DEBUG

	// TCP?
	if (ip_header->protocol == 0x06) {
		if (len < iphdrlen + sizeof(struct tcphdr)) {
			return true;
		}

		const struct tcphdr* tcp_header = (const struct tcphdr*) (pkt + iphdrlen);
		size_t tcphdrlen = tcp_header->doff * 4;
		int payload;
		if ((payload = len - (iphdrlen + tcphdrlen)) < 0) {
			return true;
		}

#if DEBUG
		unsigned short srcport = ntohs(tcp_header->source);
		unsigned short destport = ntohs(tcp_header->dest);

		printf("[TCP] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n", saddr[0], saddr[1], saddr[2], saddr[3], srcport, daddr[0], daddr[1], daddr[2], daddr[3], destport);
#endif // DEBUG

		connection* conn;
		unsigned char dir;
		if (!_M_connections.add(ip_header, tcp_header, payload, t, conn, dir)) {
			return false;
		}

		if ((!conn) || (payload == 0)) {
			return true;
		}

		packet p;
		p.payload = pkt + iphdrlen + tcphdrlen;
		p.len = payload;
		p.direction = dir;

		return _M_packet_processor.process(t, conn, p);
	} else if (ip_header->protocol == 0x11) {
		// UDP.
		if (len < iphdrlen + sizeof(struct udphdr)) {
			return true;
		}

#if DEBUG
		const struct udphdr* udp_header = (const struct udphdr*) (pkt + iphdrlen);

		unsigned short srcport = ntohs(udp_header->source);
		unsigned short destport = ntohs(udp_header->dest);

		printf("[UDP] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n", saddr[0], saddr[1], saddr[2], saddr[3], srcport, daddr[0], daddr[1], daddr[2], daddr[3], destport);
#endif // DEBUG
	}

#if DEBUG
	_M_connections.print();
#endif // DEBUG

	return true;
}
