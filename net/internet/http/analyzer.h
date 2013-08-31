#ifndef NET_INTERNET_HTTP_ANALYZER_H
#define NET_INTERNET_HTTP_ANALYZER_H

#include "net/protocol_analyzer.h"

namespace net {
	namespace internet {
		namespace http {
			class analyzer : public protocol_analyzer {
				public:
					bool process(time_t t, connection* conn, const packet& pkt);

				protected:
					static const size_t kMethodMaxLen = 20;
					static const size_t kHostMaxLen = 256;
					static const size_t kPathMaxLen = 16 * 1024;

					static const size_t kRequestMaxLen = 16 * 1024;
					static const size_t kStatusLineMaxLen = 256;

					// HTTP parsing states.
					enum {
						kBeforeMethod,
						kMethod,
						kBeforePath,
						kPath,
						kSearchingHost,
						kBeforeHostValue,
						kHost,
						kParsingStatusLine,
						kParsingServerHeaders,
						kIgnoringConnection
					};

					// Parse Status-Line.
					enum parse_result {
						kParseError,
						kParsingNotCompleted,
						kParsingCompleted
					};

					parse_result parse_status_line(connection* conn);
			};
		}
	}
}

#endif // NET_INTERNET_HTTP_ANALYZER_H
