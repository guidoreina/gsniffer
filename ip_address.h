#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include <stdint.h>

struct ip_address {
	u_int32_t ipv4;

	bool operator<(const ip_address& other) const;
	bool operator<=(const ip_address& other) const;
	bool operator==(const ip_address& other) const;
	bool operator>(const ip_address& other) const;
	bool operator>=(const ip_address& other) const;
};

inline bool ip_address::operator<(const ip_address& other) const
{
	return ipv4 < other.ipv4;
}

inline bool ip_address::operator<=(const ip_address& other) const
{
	return ipv4 <= other.ipv4;
}

inline bool ip_address::operator==(const ip_address& other) const
{
	return ipv4 == other.ipv4;
}

inline bool ip_address::operator>(const ip_address& other) const
{
	return ipv4 > other.ipv4;
}

inline bool ip_address::operator>=(const ip_address& other) const
{
	return ipv4 >= other.ipv4;
}

#endif // IP_ADDRESS_H
