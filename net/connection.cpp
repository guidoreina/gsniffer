#include <stdlib.h>
#include "net/connection.h"

void net::connection::init()
{
	state = 0;

	protocol.http.method = 0;
	protocol.http.methodlen = 0;

	protocol.http.path = 0;
	protocol.http.pathlen = 0;

	protocol.http.host = 0;
	protocol.http.hostlen = 0;

	protocol.http.offset = 0;
}
