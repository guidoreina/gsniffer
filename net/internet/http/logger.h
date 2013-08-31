#ifndef NET_INTERNET_HTTP_LOGGER_H
#define NET_INTERNET_HTTP_LOGGER_H

#include <time.h>
#include <limits.h>
#include "fs/file.h"
#include "net/ip_address.h"
#include "net/connection.h"

namespace net {
	namespace internet {
		namespace http {
			class logger {
				public:
					// Constructor.
					logger();

					// Destructor.
					~logger();

					// Create.
					bool create(const char* dir);

					// Log HTTP request.
					bool log(time_t t, const connection* conn);

				protected:
					char _M_dir[PATH_MAX + 1];

					fs::file _M_file;

					struct tm _M_time_prev_log;

					// Open log file.
					bool open(const struct tm* stm);
			};

			inline logger::~logger()
			{
				if (_M_file.fd() != -1) {
					_M_file.close();
				}
			}
		}
	}
}

#endif // NET_INTERNET_HTTP_LOGGER_H
