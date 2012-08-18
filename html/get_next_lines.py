#!/usr/bin/env python

import sys
import os
import time
import cgi
import errno

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


######################################################################
######################################################################
##                                                                  ##
## Get lines from offset.                                           ##
##                                                                  ##
######################################################################
######################################################################

def get_lines_from_offset(filename, offset, nlines, length):
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
                length[0] = 0
                return []

        # Get file size.
        f.seek(0, os.SEEK_END)
        filesize = f.tell()

        if offset >= filesize:
            length[0] = 0
            return []

        left = filesize - offset

        # Number of lines found so far.
        count = 0

        f.seek(offset)

        lines = []

        linelen = 0
        l = 0

        while left > 0:
            if left > READ_BUFFER_SIZE:
                size = READ_BUFFER_SIZE
            else:
                size = left

            # Read.
            data = f.read(size)

            left -= len(data)

            for i in range(len(data)):
                if data[i] == '\n':
                    count = count + 1

                    l += (linelen + 1)

                    if count == nlines:
                        lines.append(data[:i + 1])

                        length[0] = l
                        return lines
                    else:
                        linelen = 0
                else:
                    linelen = linelen + 1

                    # Line too long?
                    if linelen == MAX_LINE_LENGTH:
                        length[0] = 0
                        return []

            lines.append(data)

        # Close file.
        f.close()

        length[0] = l
        return lines
    except Exception as e:
        length[0] = 0
        return []


######################################################################
######################################################################
##                                                                  ##
## Build response.                                                  ##
##                                                                  ##
######################################################################
######################################################################

def build_response(date, offset, nlines):
    d = time.strftime("%Y%m%d")

    if date != d:
        offset = 0

    filename = LOG_DIR + "http_" + d + ".log"

    length = [0]
    lines = get_lines_from_offset(filename, offset, nlines, length)

    l = []
    l.append("{0}\n{1}\n".format(d, offset + length[0]))

    # Escape lines.
    for line in lines:
        l.append(cgi.escape(line))

    return l


######################################################################
######################################################################
##                                                                  ##
## get_next_lines.                                                  ##
##                                                                  ##
######################################################################
######################################################################

def get_next_lines(start_response, date, offset, nlines):
    start_response("200 OK", [("Content-Type", "text/txt")])
    return build_response(date, offset, nlines)
