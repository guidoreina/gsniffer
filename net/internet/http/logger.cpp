#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "net/internet/http/logger.h"

net::internet::http::logger::logger() : _M_file(-1)
{
	*_M_dir = 0;

	memset(&_M_time_prev_log, 0, sizeof(struct tm));
}

bool net::internet::http::logger::create(const char* dir)
{
	size_t len = strlen(dir);
	if (dir[len - 1] == '/') {
		len--;
	}

	// The name of the log files have the format:
	// http_YYYYMMDD.log
	if (len + 1 + 17 >= sizeof(_M_dir)) {
		return false;
	}

	// Check if the directory exists.
	struct stat buf;
	if (stat(dir, &buf) == 0) {
		if (!S_ISDIR(buf.st_mode)) {
			return false;
		}
	} else {
		if (mkdir(dir, 0777) < 0) {
			return false;
		}
	}

	memcpy(_M_dir, dir, len);
	_M_dir[len++] = '/';
	_M_dir[len] = 0;

	return true;
}

bool net::internet::http::logger::log(time_t t, const connection* conn)
{
	struct tm stm;
	localtime_r(&t, &stm);

	// Open log file (if required).
	if (!open(&stm)) {
		return false;
	}

	memcpy(&_M_time_prev_log, &stm, sizeof(struct tm));

	const unsigned char* saddr = (const unsigned char*) &conn->srcip.ipv4;

	struct iovec iov[12];
	char buf[64];

	iov[0].iov_base = buf;
	iov[0].iov_len = snprintf(buf, sizeof(buf), "[%04u/%02u/%02u %02u:%02u:%02u] [%u.%u.%u.%u] ", 1900 + stm.tm_year, 1 + stm.tm_mon, stm.tm_mday, stm.tm_hour, stm.tm_min, stm.tm_sec, saddr[0], saddr[1], saddr[2], saddr[3]);

	iov[1].iov_base = reinterpret_cast<void*>(conn->out->data() + conn->protocol.http.method);
	iov[1].iov_len = conn->protocol.http.methodlen;

	unsigned iovcnt = 2;

	if (conn->protocol.http.host > 0) {
		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>(" http://"));
		iov[iovcnt++].iov_len = 8;

		iov[iovcnt].iov_base = reinterpret_cast<void*>(conn->out->data() + conn->protocol.http.host);
		iov[iovcnt++].iov_len = conn->protocol.http.hostlen;
	} else {
		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>(" "));
		iov[iovcnt++].iov_len = 1;
	}

	iov[iovcnt].iov_base = reinterpret_cast<void*>(conn->out->data() + conn->protocol.http.path);
	iov[iovcnt++].iov_len = conn->protocol.http.pathlen;

	iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>(" ["));
	iov[iovcnt++].iov_len = 2;

	char status_code[16];
	iov[iovcnt].iov_base = status_code;
	iov[iovcnt++].iov_len = snprintf(status_code, sizeof(status_code), "%u", conn->protocol.http.status_code);

	iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>("] ["));
	iov[iovcnt++].iov_len = 3;

	const header_value* value;
	if ((value = conn->protocol.http.server_headers->get_header_value(header_name::SERVER)) != NULL) {
		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>(value->value));
		iov[iovcnt++].iov_len = value->len;

		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>("] ["));
		iov[iovcnt++].iov_len = 3;
	} else {
		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>("-] ["));
		iov[iovcnt++].iov_len = 4;
	}

	if ((value = conn->protocol.http.server_headers->get_header_value(header_name::CONTENT_TYPE)) != NULL) {
		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>(value->value));
		iov[iovcnt++].iov_len = value->len;

		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>("]\n"));
		iov[iovcnt++].iov_len = 2;
	} else {
		iov[iovcnt].iov_base = reinterpret_cast<void*>(const_cast<char*>("-]\n"));
		iov[iovcnt++].iov_len = 3;
	}

	return _M_file.writev(iov, iovcnt);
}

bool net::internet::http::logger::open(const struct tm* stm)
{
	// If we have to open a new log file...
	if ((stm->tm_year != _M_time_prev_log.tm_year) || (stm->tm_mon != _M_time_prev_log.tm_mon) || (stm->tm_mday != _M_time_prev_log.tm_mday)) {
		if (_M_file.fd() != -1) {
			_M_file.close();
		}
	} else {
		// If the log file is already opened...
		if (_M_file.fd() != -1) {
			return true;
		}
	}

	char filename[PATH_MAX + 1];
	snprintf(filename, sizeof(filename), "%s/http_%04u%02u%02u.log", _M_dir, 1900 + stm->tm_year, 1 + stm->tm_mon, stm->tm_mday);

	if (!_M_file.open(filename, O_WRONLY | O_CREAT, 0644)) {
		return false;
	}

	return (_M_file.seek(0, SEEK_END) != (off_t) -1);
}
