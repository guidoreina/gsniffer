#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include "file.h"

bool file::open(const char* pathname, int flags)
{
	if ((_M_fd = ::open(pathname, flags)) < 0) {
		return false;
	}

	return true;
}

bool file::open(const char* pathname, int flags, mode_t mode)
{
	if ((_M_fd = ::open(pathname, flags, mode)) < 0) {
		return false;
	}

	return true;
}

void file::close()
{
	if (_M_fd != -1) {
		::close(_M_fd);
		_M_fd = -1;
	}
}

ssize_t file::read(void* buf, size_t count)
{
	do {
		ssize_t ret;
		if ((ret = ::read(_M_fd, buf, count)) < 0) {
			if ((errno != EINTR) && (errno != EAGAIN)) {
				return -1;
			}
		} else {
			return ret;
		}
	} while (true);
}

ssize_t file::pread(void* buf, size_t count, off_t offset)
{
#if HAVE_PREAD
	do {
		ssize_t ret;
		if ((ret = ::pread(_M_fd, buf, count, offset)) < 0) {
			if ((errno != EINTR) && (errno != EAGAIN)) {
				return -1;
			}
		} else {
			return ret;
		}
	} while (true);
#else
	if (seek(_M_fd, offset, SEEK_SET) != offset) {
		return -1;
	}

	return read(buf, count);
#endif
}

ssize_t file::readv(const struct iovec* iov, int iovcnt)
{
	do {
		ssize_t ret;
		if ((ret = ::readv(_M_fd, iov, iovcnt)) < 0) {
			if ((errno != EINTR) && (errno != EAGAIN)) {
				return -1;
			}
		} else {
			return ret;
		}
	} while (true);
}

bool file::write(const void* buf, size_t count)
{
	const char* ptr = (const char*) buf;
	size_t written = 0;

	do {
		ssize_t ret;
		if ((ret = ::write(_M_fd, ptr + written, count - written)) < 0) {
			if ((errno != EINTR) && (errno != EAGAIN)) {
				return false;
			}
		} else if (ret > 0) {
			written += ret;
		}
	} while (written < count);

	return true;
}

bool file::pwrite(const void* buf, size_t count, off_t offset)
{
#if HAVE_PREAD
	const char* ptr = (const char*) buf;
	size_t written = 0;

	do {
		ssize_t ret;
		if ((ret = ::pwrite(_M_fd, ptr + written, count - written, offset)) < 0) {
			if ((errno != EINTR) && (errno != EAGAIN)) {
				return false;
			}
		} else if (ret > 0) {
			offset += ret;
			written += ret;
		}
	} while (written < count);

	return true;
#else
	if (seek(_M_fd, offset, SEEK_SET) != offset) {
		return false;
	}

	return write(buf, count);
#endif
}

bool file::writev(const struct iovec* iov, int iovcnt)
{
	if ((iovcnt < 0) || (iovcnt > IOV_MAX)) {
		return false;
	} else if (iovcnt == 0) {
		return true;
	}

	struct iovec vec[IOV_MAX];
	size_t count = 0;

	for (int i = 0; i < iovcnt; i++) {
		vec[i].iov_base = iov[i].iov_base;
		vec[i].iov_len = iov[i].iov_len;

		count += vec[i].iov_len;
	}

	struct iovec* v = vec;
	size_t written = 0;

	do {
		ssize_t ret;
		if ((ret = ::writev(_M_fd, v, iovcnt)) < 0) {
			if ((errno != EINTR) && (errno != EAGAIN)) {
				return false;
			}
		} else if (ret > 0) {
			written += ret;

			if (written == count) {
				return true;
			}

			while ((size_t) ret >= v->iov_len) {
				ret -= v->iov_len;
				v++;
			}

			if (ret > 0) {
				v->iov_base = (char*) v->iov_base + ret;
				v->iov_len -= ret;
			}
		}
	} while (true);
}

bool file::truncate(off_t length)
{
	if (::ftruncate(_M_fd, length) < 0) {
		return false;
	}

	return true;
}
