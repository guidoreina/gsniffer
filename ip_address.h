#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include <stdint.h>

struct ip_address {
	u_int32_t ipv4;

	bool operator<(const ip_address& other) const;
	bool operator<=(const ip_address& other) const;
	bool operator==(const ip_address& other) const;
	bool operator!=(const ip_address& other) const;
	bool operator>(const ip_address& other) const;
	bool operator>=(const ip_address& other) const;

	static int compare(const ip_address& ip1, const ip_address& ip2);
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

inline bool ip_address::operator!=(const ip_address& other) const
{
	return ipv4 != other.ipv4;
}

inline bool ip_address::operator>(const ip_address& other) const
{
	return ipv4 > other.ipv4;
}

inline bool ip_address::operator>=(const ip_address& other) const
{
	return ipv4 >= other.ipv4;
}

inline int ip_address::compare(const ip_address& ip1, const ip_address& ip2)
{
	const unsigned char* s1 = (const unsigned char*) &ip1.ipv4;
	const unsigned char* s2 = (const unsigned char*) &ip2.ipv4;

	for (unsigned i = 0; i < sizeof(u_int32_t); i++) {
		if (s1[i] < s2[i]) {
			return -1;
		} else if (s1[i] > s2[i]) {
			return 1;
		}
	}

	return 0;
}

#endif // IP_ADDRESS_H
