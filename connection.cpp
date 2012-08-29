#include <stdlib.h>
#include "connection.h"

const size_t connection::IN_BUFFER_ALLOC = 512;
const size_t connection::OUT_BUFFER_ALLOC = 512;

void connection::init()
{
	state = 0;

	protocol.http.method = 0;
	protocol.http.methodlen = 0;

	protocol.http.path = 0;
	protocol.http.pathlen = 0;

	protocol.http.host = 0;
	protocol.http.hostlen = 0;
}
