#ifndef HTTP_LOGGER_H
#define HTTP_LOGGER_H

#include <stdint.h>
#include <time.h>
#include <limits.h>
#include "file.h"

class http_logger {
	public:
		// Constructor.
		http_logger();

		// Destructor.
		~http_logger();

		// Create.
		bool create(const char* dir);

		// Log HTTP request.
		bool log(time_t t, u_int32_t srcip, const char* method, size_t methodlen, const char* url, size_t urllen);
		bool log(time_t t, u_int32_t srcip, const char* method, size_t methodlen, const char* host, size_t hostlen, const char* url, size_t urllen);

	protected:
		char _M_dir[PATH_MAX + 1];

		file _M_file;

		struct tm _M_time_prev_log;

		// Open log file.
		bool open(const struct tm* stm);
};

inline http_logger::~http_logger()
{
}

inline bool http_logger::log(time_t t, u_int32_t srcip, const char* method, size_t methodlen, const char* url, size_t urllen)
{
	return log(t, srcip, method, methodlen, NULL, 0, url, urllen);
}

#endif // HTTP_LOGGER_H
