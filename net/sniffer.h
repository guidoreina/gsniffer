#ifndef NET_SNIFFER_H
#define NET_SNIFFER_H

#include <net/if.h>
#include "net/connection_list.h"
#include "net/packet_processor.h"
#include "net/internet/http/logger.h"

namespace net {
	class sniffer {
		public:
			static const size_t kMinSize = 1024 * 1024;
			static const size_t kMaxSize = 1024 * 1024 * 1024;
			static const size_t kDefaultSize = 100 * 1024 * 1024;

			// Constructor.
			sniffer();

			// Destructor.
			~sniffer();

			// Create.
			bool create(const char* interface, const char* dir, size_t size = kDefaultSize);

			// Start.
			void start();

			// Stop.
			void stop();

			// On alarm.
			void on_alarm();

			// Get HTTP logger.
			internet::http::logger* get_http_logger();

		protected:
			static const char* kConnectionsFilename;
			static const char* kPipeFilename;

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
			internet::http::logger _M_http_logger;

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

	inline internet::http::logger* sniffer::get_http_logger()
	{
		return &_M_http_logger;
	}
}

#endif // NET_SNIFFER_H
