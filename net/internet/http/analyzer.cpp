#include <stdlib.h>
#include <string.h>
#include "net/internet/http/analyzer.h"
#include "net/sniffer.h"
#include "macros/macros.h"

extern net::sniffer gsniffer;

bool net::internet::http::analyzer::process(time_t t, connection* conn, const packet& pkt)
{
	if (conn->state == kIgnoringConnection) {
		return true;
	}

	const unsigned char* begin;
	size_t count;

	if (pkt.direction == kOutgoingPacket) {
		if (conn->state >= kParsingStatusLine) {
			return true;
		}

		count = conn->out ? conn->out->count() : 0;

		if (!conn->append_out(reinterpret_cast<const char*>(pkt.payload), pkt.len)) {
			return false;
		}

		begin = reinterpret_cast<const unsigned char*>(conn->out->data()) + count;
	} else {
		if (conn->state < kParsingStatusLine) {
			return true;
		}

		count = conn->in ? conn->in->count() : 0;

		if (!conn->append_in(reinterpret_cast<const char*>(pkt.payload), pkt.len)) {
			return false;
		}

		begin = reinterpret_cast<const unsigned char*>(conn->in->data()) + count;
	}

	count += pkt.len;

	const unsigned char* ptr = begin;
	const unsigned char* end = ptr + pkt.len;

	size_t methodlen = conn->protocol.http.methodlen;
	size_t pathlen = conn->protocol.http.pathlen;
	size_t hostlen = conn->protocol.http.hostlen;

	int state = conn->state;

	do {
		unsigned char c = *ptr;

		switch (state) {
			case kBeforeMethod: // Before method.
				if ((c >= 'A') && (c <= 'Z')) {
					conn->protocol.http.method = count - (end - ptr);
					methodlen = 1;

					state = kMethod; // Method.
				} else if ((c != ' ') && (c != '\t') && (c != '\r') && (c != '\n')) {
					// Ignore connection.
					conn->state = kIgnoringConnection;
					return true;
				}

				break;
			case kMethod: // Method.
				if ((c >= 'A') && (c <= 'Z')) {
					if (++methodlen > kMethodMaxLen) {
						// Ignore connection.
						conn->state = kIgnoringConnection;
						return true;
					}
				} else if ((c == ' ') || (c == '\t')) {
					conn->protocol.http.methodlen = methodlen;

					state = kBeforePath; // Before path.
				} else {
					// Ignore connection.
					conn->state = kIgnoringConnection;
					return true;
				}

				break;
			case kBeforePath: // Before path.
				if (c > ' ') {
					conn->protocol.http.path = count - (end - ptr);
					pathlen = 1;

					state = kPath; // Path.
				} else if ((c != ' ') && (c != '\t')) {
					// Ignore connection.
					conn->state = kIgnoringConnection;
					return true;
				}

				break;
			case kPath: // Path.
				switch (c) {
					case ' ':
					case '\t':
					case '\r':
					case '\n':
						conn->protocol.http.pathlen = pathlen;

						if ((pathlen > 7) && (strncasecmp(conn->out->data() + conn->protocol.http.path, "http://", 7) == 0)) {
							conn->protocol.http.host = 0;

							conn->protocol.http.offset = 0;

							conn->state = kParsingStatusLine;
							conn->protocol.http.substate = 0;

							return true;
						}

						state = kSearchingHost; // Searching host.

						break;
					default:
						if (c > ' ') {
							if (++pathlen > kPathMaxLen) {
								// Ignore connection.
								conn->state = kIgnoringConnection;
								return true;
							}
						} else {
							// Ignore connection.
							conn->state = kIgnoringConnection;
							return true;
						}
				}

				break;
			case kSearchingHost: // Searching host.
				ptr = reinterpret_cast<const unsigned char*>(conn->out->data()) + conn->protocol.http.path + conn->protocol.http.pathlen;

				if ((ptr = reinterpret_cast<const unsigned char*>(memmem(ptr, end - ptr, "Host:", 5))) == NULL) {
					// Host header might come in the next packet.
					ptr = end;

					continue;
				} else {
					ptr += 5;

					state = kBeforeHostValue; // Before host value.

					continue;
				}

				break;
			case kBeforeHostValue: // Before host value.
				if (c > ' ') {
					conn->protocol.http.host = count - (end - ptr);
					hostlen = 1;

					state = kHost; // Host.
				} else if ((c != ' ') && (c != '\t')) {
					// Ignore connection.
					conn->state = kIgnoringConnection;
					return true;
				}

				break;
			case kHost: // Host.
				switch (c) {
					case ' ':
					case '\t':
					case '\r':
					case '\n':
						conn->protocol.http.hostlen = hostlen;

						conn->protocol.http.offset = 0;

						conn->state = kParsingStatusLine;
						conn->protocol.http.substate = 0;

						return true;
					default:
						if (c > ' ') {
							if (++hostlen > kHostMaxLen) {
								// Ignore connection.
								conn->state = kIgnoringConnection;
								return true;
							}
						} else {
							// Ignore connection.
							conn->state = kIgnoringConnection;
							return true;
						}
				}

				break;
			case kParsingStatusLine: // Parsing status-line.
				switch (parse_status_line(conn)) {
					case kParseError:
						// Ignore connection.
						conn->state = kIgnoringConnection;
						return true;
					case kParsingNotCompleted:
						return true;
					case kParsingCompleted:
						ptr = reinterpret_cast<const unsigned char*>(conn->in->data()) + conn->protocol.http.offset;

						state = kParsingServerHeaders;
						continue;
				}

				break;
			case kParsingServerHeaders: // Parsing server headers.
				switch (conn->protocol.http.parse_server_headers(conn->in->data() + conn->protocol.http.offset, count - conn->protocol.http.offset)) {
					case headers::PARSE_NO_MEMORY:
					case headers::PARSE_INVALID_HEADER:
					case headers::PARSE_HEADERS_TOO_LARGE:
						// Ignore connection.
						conn->state = kIgnoringConnection;
						return true;
					case headers::PARSE_NOT_END_OF_HEADER:
						return true;
					case headers::PARSE_END_OF_HEADER:
						if (!gsniffer.get_http_logger()->log(t, conn)) {
							return false;
						}

						conn->state = kIgnoringConnection;
						return true;
				}

				break;
		}

		ptr++;
	} while (ptr < end);

	if (pkt.direction == kOutgoingPacket) {
		// Request too large?
		if (count > kRequestMaxLen) {
			// Ignore connection.
			conn->state = kIgnoringConnection;
			return true;
		}
	}

	conn->state = state;

	conn->protocol.http.methodlen = methodlen;
	conn->protocol.http.pathlen = pathlen;
	conn->protocol.http.hostlen = hostlen;

	return true;
}

net::internet::http::analyzer::parse_result net::internet::http::analyzer::parse_status_line(connection* conn)
{
	const char* data = conn->in->data();
	size_t len = conn->in->count();
	unsigned short offset = conn->protocol.http.offset;

	while (offset < len) {
		unsigned char c = (unsigned char) data[offset];
		switch (conn->protocol.http.substate) {
			case 0: // Initial state.
				if ((c == 'H') || (c == 'h')) {
					conn->protocol.http.substate = 1; // [H]TTP/<major>.<minor>
				} else if (!IS_WHITE_SPACE(c)) {
					return kParseError;
				}

				break;
			case 1: // [H]TTP/<major>.<minor>
				if ((c == 'T') || (c == 't')) {
					conn->protocol.http.substate = 2; // H[T]TP/<major>.<minor>
				} else {
					return kParseError;
				}

				break;
			case 2: // H[T]TP/<major>.<minor>
				if ((c == 'T') || (c == 't')) {
					conn->protocol.http.substate = 3; // HT[T]P/<major>.<minor>
				} else {
					return kParseError;
				}

				break;
			case 3: // HT[T]P/<major>.<minor>
				if ((c == 'P') || (c == 'p')) {
					conn->protocol.http.substate = 4; // HTT[P]/<major>.<minor>
				} else {
					return kParseError;
				}

				break;
			case 4: // HTT[P]/<major>.<minor>
				if (c == '/') {
					conn->protocol.http.substate = 5; // HTTP[/]<major>.<minor>
				} else {
					return kParseError;
				}

				break;
			case 5: // HTTP[/]<major>.<minor>
				if ((c >= '0') && (c <= '9')) {
					conn->protocol.http.major_number = c - '0';
					if (conn->protocol.http.major_number > 1) {
						return kParseError;
					}

					conn->protocol.http.substate = 6; // HTTP/[<major>].<minor>
				} else {
					return kParseError;
				}

				break;
			case 6: // HTTP/[<major>].<minor>
				if (c == '.') {
					conn->protocol.http.substate = 7; // HTTP/<major>[.]<minor>
				} else {
					return kParseError;
				}

				break;
			case 7: // HTTP/<major>[.]<minor>
				if ((c >= '0') && (c <= '9')) {
					conn->protocol.http.minor_number = c - '0';
					if ((conn->protocol.http.major_number == 1) && (conn->protocol.http.minor_number > 1)) {
						return kParseError;
					}

					conn->protocol.http.substate = 8; // HTTP/<major>.[<minor>]
				} else {
					return kParseError;
				}

				break;
			case 8: // HTTP/<major>.[<minor>]
				if (IS_WHITE_SPACE(c)) {
					conn->protocol.http.substate = 9; // Whitespace after HTTP-Version.
				} else {
					return kParseError;
				}

				break;
			case 9: // Whitespace after HTTP-Version.
				if ((c >= '0') && (c <= '9')) {
					conn->protocol.http.status_code = c - '0';

					conn->protocol.http.substate = 10; // Status-Code.
				} else if (!IS_WHITE_SPACE(c)) {
					return kParseError;
				}

				break;
			case 10: // Status-Code.
				if ((c >= '0') && (c <= '9')) {
					conn->protocol.http.status_code = (conn->protocol.http.status_code * 10) + (c - '0');
					if (conn->protocol.http.status_code > 999) {
						return kParseError;
					}
				} else if (IS_WHITE_SPACE(c)) {
					conn->protocol.http.substate = 11; // Whitespace after Status-Code.
				} else if (c == '\r') {
					conn->protocol.http.substate = 12; // '\r' at the end of status line.
				} else if (c == '\n') {
					conn->protocol.http.offset = ++offset;

					return kParsingCompleted;
				} else {
					return kParseError;
				}

				break;
			case 11: // Whitespace after Status-Code.
				if (c == '\r') {
					conn->protocol.http.substate = 12; // '\r' at the end of status line.
				} else if (c == '\n') {
					conn->protocol.http.offset = ++offset;

					return kParsingCompleted;
				} else if (c < ' ') {
					return kParseError;
				}

				break;
			case 12: // '\r' at the end of status line.
				if (c == '\n') {
					conn->protocol.http.offset = ++offset;

					return kParsingCompleted;
				} else {
					return kParseError;
				}

				break;
		}

		if (++offset == kStatusLineMaxLen) {
			return kParseError;
		}
	}

	conn->protocol.http.offset = offset;

	return kParsingNotCompleted;
}
