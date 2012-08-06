#ifndef SNIFFER_H
#define SNIFFER_H

#include <net/if.h>
#include "connection_list.h"

class sniffer {
	public:
		static const size_t MIN_SIZE;
		static const size_t MAX_SIZE;
		static const size_t DEFAULT_SIZE;

		// Constructor.
		sniffer();

		// Destructor.
		~sniffer();

		// Create.
		bool create(const char* interface, size_t size = DEFAULT_SIZE);

		// Start.
		void start();

		// Stop.
		void stop();

		// On alarm.
		void on_alarm();

	protected:
		static const char* CONNECTIONS_FILENAME;
		static const char* PIPE_FILENAME;

		char _M_interface[IFNAMSIZ];
		int _M_fd;

		void* _M_buf;
		size_t _M_size;

		unsigned char** _M_frames;
		unsigned _M_number_frames;

		unsigned _M_idx;

		connection_list _M_connections;

		int _M_pipe;

		bool _M_running;

		bool _M_handle_alarm;

		// Process IP packet.
		bool process_ip_packet(const unsigned char* pkt, size_t len, unsigned t);
};

inline void sniffer::stop()
{
	_M_running = false;
}

inline void sniffer::on_alarm()
{
	_M_handle_alarm = true;
}

#endif // SNIFFER_H
