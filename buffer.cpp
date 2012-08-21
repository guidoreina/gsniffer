#include <stdio.h>
#include "buffer.h"

const size_t buffer::DEFAULT_INITIAL_SIZE = 64;

bool buffer::allocate(size_t size)
{
	size += _M_used;
	if (size <= _M_size) {
		return true;
	}

	size_t s;
	if (_M_size == 0) {
		s = _M_initial_size;
	} else {
		size_t tmp;
		if ((tmp = _M_size * 2) < _M_size) {
			// Overflow.
			return false;
		}

		s = tmp;
	}

	while (s < size) {
		size_t tmp;
		if ((tmp = s * 2) < s) {
			// Overflow.
			return false;
		}

		s = tmp;
	}

	char* data = (char*) realloc(_M_data, s);
	if (!data) {
		return false;
	}

	_M_data = data;
	_M_size = s;

	return true;
}

bool buffer::vformat(const char* format, va_list ap)
{
	if (!allocate(_M_initial_size)) {
		return false;
	}

	int size = _M_size - _M_used;

	do {
		int n = vsnprintf(_M_data + _M_used, size, format, ap);
		if (n > -1) {
			if (n < size) {
				_M_used += n;
				break;
			}

			size = n + 1;
		} else {
			size *= 2;
		}

		if (!allocate(size)) {
			return false;
		}
	} while (true);

	return true;
}
