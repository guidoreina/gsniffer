#ifndef SNIFFER_H
#define SNIFFER_H

#include <net/if.h>
#include "connection_list.h"
#include "packet_processor.h"
#include "http_logger.h"

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
		bool create(const char* interface, const char* dir, size_t size = DEFAULT_SIZE);

		// Start.
		void start();

		// Stop.
		void stop();

		// On alarm.
		void on_alarm();

		// Get HTTP logger.
		http_logger* get_http_logger();

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

		packet_processor _M_packet_processor;
		http_logger _M_http_logger;

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

inline http_logger* sniffer::get_http_logger()
{
	return &_M_http_logger;
}

#endif // SNIFFER_H
