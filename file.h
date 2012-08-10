#ifndef FILE_H
#define FILE_H

#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>

class file {
	public:
		// Constructor.
		file();
		file(int fd);

		// Destructor.
		~file();

		// Get file descriptor.
		int fd() const;

		// Set file descriptor.
		void fd(int desc);

		// Open.
		bool open(const char* pathname, int flags);
		bool open(const char* pathname, int flags, mode_t mode);

		// Close.
		void close();

		// Read.
		ssize_t read(void* buf, size_t count);

		// Read at a given offset.
		ssize_t pread(void* buf, size_t count, off_t offset);

		// Read into multiple buffers.
		ssize_t readv(const struct iovec* iov, int iovcnt);

		// Write.
		bool write(const void* buf, size_t count);

		// Write at a given offset.
		bool pwrite(const void* buf, size_t count, off_t offset);

		// Write from multiple buffers.
		bool writev(const struct iovec* iov, int iovcnt);

		// Seek.
		off_t seek(off_t offset, int whence);

		// Truncate.
		bool truncate(off_t length);

	protected:
		int _M_fd;
};

inline file::file()
{
	_M_fd = -1;
}

inline file::file(int fd)
{
	_M_fd = fd;
}

inline file::~file()
{
	close();
}

inline int file::fd() const
{
	return _M_fd;
}

inline void file::fd(int desc)
{
	_M_fd = desc;
}

inline off_t file::seek(off_t offset, int whence)
{
	return ::lseek(_M_fd, offset, whence);
}

#endif // FILE_H
