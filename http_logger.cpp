#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "http_logger.h"

http_logger::http_logger()
{
	*_M_dir = 0;

	memset(&_M_time_prev_log, 0, sizeof(struct tm));
}

bool http_logger::create(const char* dir)
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

bool http_logger::log(time_t t, const ip_address& srcip, const char* method, size_t methodlen, const char* host, size_t hostlen, const char* url, size_t urllen)
{
	struct tm stm;
	localtime_r(&t, &stm);

	// Open log file (if required).
	if (!open(&stm)) {
		return false;
	}

	memcpy(&_M_time_prev_log, &stm, sizeof(struct tm));

	const unsigned char* saddr = (const unsigned char*) &srcip.ipv4;

	struct iovec iov[6];
	char buf[64];

	iov[0].iov_base = buf;
	iov[0].iov_len = snprintf(buf, sizeof(buf), "[%04u/%02u/%02u %02u:%02u:%02u] [%u.%u.%u.%u] ", 1900 + stm.tm_year, 1 + stm.tm_mon, stm.tm_mday, stm.tm_hour, stm.tm_min, stm.tm_sec, saddr[0], saddr[1], saddr[2], saddr[3]);

	iov[1].iov_base = (void*) method;
	iov[1].iov_len = methodlen;

	unsigned iovcnt = 2;

	if (host) {
		iov[iovcnt].iov_base = (void*) " http://";
		iov[iovcnt++].iov_len = 8;

		iov[iovcnt].iov_base = (void*) host;
		iov[iovcnt++].iov_len = hostlen;
	} else {
		iov[iovcnt].iov_base = (void*) " ";
		iov[iovcnt++].iov_len = 1;
	}

	iov[iovcnt].iov_base = (void*) url;
	iov[iovcnt++].iov_len = urllen;

	iov[iovcnt].iov_base = (void*) "\n";
	iov[iovcnt++].iov_len = 1;

	return _M_file.writev(iov, iovcnt);
}

bool http_logger::open(const struct tm* stm)
{
	// If we have to open a new log file...
	if ((stm->tm_year != _M_time_prev_log.tm_year) || (stm->tm_mon != _M_time_prev_log.tm_mon) || (stm->tm_mday != _M_time_prev_log.tm_mday)) {
		_M_file.close();
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
