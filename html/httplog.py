#!/usr/bin/env python

import sys
import os
import time
import cgi
import errno
from string import Template

######################################################################
######################################################################
##                                                                  ##
## Constants.                                                       ##
##                                                                  ##
######################################################################
######################################################################

# Read in chunks of 8 KB.
READ_BUFFER_SIZE = 8 * 1024

# Minimum number of lines.
MIN_LINES = 1

# Maximum number of lines.
MAX_LINES = 200

# Maximum line length.
MAX_LINE_LENGTH = 2048

# Directory which contains the HTTP log files.
LOG_DIR = "/home/guido/programming/c++/sniffer/log/"

# Error page.
ERROR_PAGE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \
\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\
<html xmlns=\"http://www.w3.org/1999/xhtml\">\
<head>\
<title>HTTP requests</title>\
<link rel=\"stylesheet\" href=\"style.css\"/>\
</head>\
<body>\
<h1>Error</h1>\
</body>\
</html>"


######################################################################
######################################################################
##                                                                  ##
## Add HTML header.                                                 ##
##                                                                  ##
######################################################################
######################################################################

def add_html_header(response, date, filesize):
    template = Template("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \
\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\
<html xmlns=\"http://www.w3.org/1999/xhtml\">\
<head>\
<title>HTTP requests</title>\
<link rel=\"stylesheet\" href=\"style.css\"/>\
<script type=\"text/javascript\">\
var date = ${date};\
var offset = ${offset};\
</script>\
<script type=\"text/javascript\" src=\"last_update.js\"></script>\
<script type=\"text/javascript\" src=\"get_next_lines.js\"></script>\
</head>\
<body>\
<p class=\"last_update\" id=\"last_update\"></p>\
<p>\
<textarea id=\"http_requests\" class=\"logarea\" rows=\"1\" cols=\"1\">")

    response.append(template.substitute(dict(date = date, offset = filesize)))


######################################################################
######################################################################
##                                                                  ##
## Add HTML footer.                                                 ##
##                                                                  ##
######################################################################
######################################################################

def add_html_footer(response):
    response.append("</textarea></p></body></html>")


######################################################################
######################################################################
##                                                                  ##
## tail.                                                            ##
##                                                                  ##
######################################################################
######################################################################

def tail(filename, nlines, filesize, lines):
    try:
        if nlines < MIN_LINES:
            nlines = MIN_LINES
        elif nlines > MAX_LINES:
            nlines = MAX_LINES

        # Open file for reading.
        try:
            f = open(filename, "rb")
        except IOError as e:
            if e.errno == errno.ENOENT:
                return True

        # Get file size.
        f.seek(0, os.SEEK_END)
        filesize[0] = f.tell()

        # Number of lines found so far.
        count = 0

        offset = filesize[0]
        start = 0

        while offset > 0:
            if offset + start > READ_BUFFER_SIZE:
                size = READ_BUFFER_SIZE
                offset -= (READ_BUFFER_SIZE - start)
            else:
                size = offset + start
                offset = 0

            # Seek.
            f.seek(offset)

            # Read.
            data = f.read(size)

            linelen = 0

            for i in range(len(data) - 1, -1, -1):
                if data[i] == '\n':
                    if i != len(data) - 1:
                        count = count + 1

                        if count == nlines:
                            lines.append(data[i + 1:])
                            lines.reverse()

                            return True
                        else:
                            start = i + 1
                            linelen = 0
                else:
                    linelen = linelen + 1

                    # Line too long?
                    if linelen == MAX_LINE_LENGTH:
                        del lines[:]
                        return False

            lines.append(data[start:])

        # Close file.
        f.close()

        lines.append(data[:start])
        lines.reverse()

        return True
    except Exception as e:
        del lines[:]
        return False


######################################################################
######################################################################
##                                                                  ##
## Build response.                                                  ##
##                                                                  ##
######################################################################
######################################################################

def build_response(nlines):
    date = time.strftime("%Y%m%d")
    filename = LOG_DIR + "http_" + date + ".log"

    filesize = [0]
    lines = []
    if not tail(filename, nlines, filesize, lines):
        return [ERROR_PAGE]

    response = []
    add_html_header(response, date, filesize[0])

    # Escape lines.
    for line in lines:
        response.append(cgi.escape(line))

    add_html_footer(response)

    return response


######################################################################
######################################################################
##                                                                  ##
## httplog.                                                         ##
##                                                                  ##
######################################################################
######################################################################

def httplog(start_response, nlines):
    start_response("200 OK", [("Content-Type", "text/html")])
    return build_response(nlines)
