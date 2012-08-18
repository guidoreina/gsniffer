#!/usr/bin/env python

import urlparse
from flup.server.fcgi import WSGIServer
import connections
import httplog
import get_next_lines

######################################################################
######################################################################
##                                                                  ##
## Constants.                                                       ##
##                                                                  ##
######################################################################
######################################################################

# Address to bind to.
BIND_ADDRESS = ('127.0.0.1', 9000)

# Default number of lines.
DEFAULT_LINES = 100

# Not found error page.
NOT_FOUND = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \
\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\
<html xmlns=\"http://www.w3.org/1999/xhtml\">\
<head>\
<title>Not found</title>\
</head>\
<body>\
<h1>HTTP/1.1 404 Not found</h1>\
</body>\
</html>"


######################################################################
######################################################################
##                                                                  ##
## myapp.                                                           ##
##                                                                  ##
######################################################################
######################################################################

def myapp(environ, start_response):
    # Get QUERY_STRING.
    query_string = environ.get("QUERY_STRING")
    if query_string == None:
        start_response("404 Not found", [("Content-Type", "text/html")])
        return [NOT_FOUND]

    args = urlparse.parse_qs(query_string)

    arg = args.get("script")
    if arg == None:
        start_response("404 Not found", [("Content-Type", "text/html")])
        return [NOT_FOUND]

    script = arg[0]

    if script == "connections":
        return connections.connections(start_response)
    elif script == "httplog":
        arg = args.get("lines", [DEFAULT_LINES])[0]
        try:
            nlines = int(arg)
        except ValueError:
            nlines = DEFAULT_LINES

        return httplog.httplog(start_response, nlines)
    elif script == "get_next_lines":
        arg = args.get("date")
        if arg == None:
            start_response("404 Not found", [("Content-Type", "text/html")])
            return [NOT_FOUND]

        date = arg[0]
        if len(date) != 8:
            start_response("404 Not found", [("Content-Type", "text/html")])
            return [NOT_FOUND]

        arg = args.get("offset")
        if arg == None:
            start_response("404 Not found", [("Content-Type", "text/html")])
            return [NOT_FOUND]

        try:
            offset = int(arg[0])
        except ValueError:
            start_response("404 Not found", [("Content-Type", "text/html")])
            return [NOT_FOUND]

        arg = args.get("lines", [DEFAULT_LINES])[0]
        try:
            nlines = int(arg)
        except ValueError:
            nlines = DEFAULT_LINES

        return get_next_lines.get_next_lines(start_response, date, offset, nlines)
    else:
        start_response("404 Not found", [("Content-Type", "text/html")])
        return [NOT_FOUND]


if __name__ == "__main__":
    WSGIServer(myapp, bindAddress = BIND_ADDRESS, multiplexed = True).run()
