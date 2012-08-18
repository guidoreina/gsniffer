#!/usr/bin/env python

import sys
import time
import datetime
import os

######################################################################
######################################################################
##                                                                  ##
## Constants.                                                       ##
##                                                                  ##
######################################################################
######################################################################

# Read in chunks of 8 KB.
READ_BUFFER_SIZE = 8 * 1024

# Maximum number of lines.
MAX_LINES = 200

# Name of the file which contains the list of connections.
CONNECTIONS_FILENAME = "/home/guido/programming/c++/sniffer/connections.txt"

# Name of the named pipe to communicate with the sniffer.
PIPE_FILENAME = "/tmp/gsniffer.pipe"

# Error page.
ERROR_PAGE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \
\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\
<html xmlns=\"http://www.w3.org/1999/xhtml\">\
<head>\
<title>Connections</title>\
<link rel=\"stylesheet\" href=\"style.css\"/>\
</head>\
<body>\
<h1>Error</h1>\
</body>\
</html>"


######################################################################
######################################################################
##                                                                  ##
## Format transfer.                                                 ##
##                                                                  ##
######################################################################
######################################################################

def format_transfer(transfer):
    if transfer > 1024:
        if transfer > 1024 * 1024:
            if transfer > 1024 * 1024 * 1024:
                return "{0}B ({1:0.2f} GB)".format(transfer, transfer / (1024 * 1024 * 1024.0))
            else:
                return "{0}B ({1:0.2f} MB)".format(transfer, transfer / (1024 * 1024.0))
        else:
            return "{0}B ({1:0.2f} KB)".format(transfer, transfer / 1024.0)
    else:
        return "{0}B".format(transfer)


######################################################################
######################################################################
##                                                                  ##
## Add HTML header.                                                 ##
##                                                                  ##
######################################################################
######################################################################

def add_html_header(response):
    response.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \
\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\
<html xmlns=\"http://www.w3.org/1999/xhtml\">\
<head>\
<meta http-equiv=\"refresh\" content=\"5\"/>\
<title>Connections</title>\
<link rel=\"stylesheet\" href=\"style.css\"/>\
<script type=\"text/javascript\" src=\"last_update.js\"></script>\
<script type=\"text/javascript\" src=\"connections.js\"></script>\
</head>\
<body>\
<p class=\"last_update\" id=\"last_update\"></p>\
<table class=\"connection_table\">\
<thead>\
<tr>\
<th>Source IP</th>\
<th>Destination IP</th>\
<th>Connection</th>\
<th>Creation</th>\
<th>Last activity</th>\
<th>Uploaded</th>\
<th>Downloaded</th>\
</tr>\
</thead>\
<tbody>")


######################################################################
######################################################################
##                                                                  ##
## Add connections.                                                 ##
##                                                                  ##
######################################################################
######################################################################

def add_connections(response, nsrcip, srcip, connections, destips):
    if len(connections) == 1:
        response.append("<tr><td class=\"srcip{0}\">{1}</td>"\
            .format(nsrcip % 4, srcip))
    else:
        response.append("<tr><td class=\"srcip{0}\" rowspan=\"{1}\">{2}</td>"\
            .format(nsrcip % 4, len(connections) + 1, srcip))

    # Index in connection list.
    idx = 0

    total_uploaded = 0
    total_downloaded = 0

    for i in range(len(destips)):
        style = i % 4

        count = destips[i][1]
        if count == 1:
            response.append("<td class=\"destip{0}\">{1}</td>"\
                .format(style, destips[i][0]))
        else:
            response.append("<td class=\"destip{0}\" rowspan=\"{1}\">{2}</td>"\
                .format(style, count, destips[i][0]))

        for j in range(count):
            response.append("<td class=\"destip{0}\">{1} {2} {3}</td>"\
                .format(style,\
                        connections[idx][0],\
                        connections[idx][1],\
                        connections[idx][2]))

            # Creation time.
            creation = datetime.datetime.fromtimestamp(int(connections[idx][3]))
            response.append("<td class=\"destip{0}\">{1}</td>"\
                .format(style, creation.isoformat(' ')))

            # Timestamp of last activity.
            timestamp = datetime.datetime.fromtimestamp(int(connections[idx][4]))
            response.append("<td class=\"destip{0}\">{1}</td>"\
                .format(style, timestamp.isoformat(' ')))

            # Uploaded.
            uploaded = int(connections[idx][5])
            response.append("<td class=\"destip{0}\">{1}</td>"\
                .format(style, format_transfer(uploaded)))

            # Downloaded.
            downloaded = int(connections[idx][6])
            response.append("<td class=\"destip{0}\">{1}</td>"\
                .format(style, format_transfer(downloaded)))

            total_uploaded += uploaded
            total_downloaded += downloaded

            idx = idx + 1

            if j < count - 1:
                response.append("</tr><tr>")

        if i < len(destips) - 1:
            response.append("</tr><tr>")

    if len(connections) > 1:
        response.append("</tr><tr><td class=\"total_by_srcip\" colspan=\"6\">\
Total uploaded: {0}, total downloaded: {1}</td></tr>"\
            .format(format_transfer(total_uploaded),
                    format_transfer(total_downloaded)))
    else:
        response.append("</tr>")


######################################################################
######################################################################
##                                                                  ##
## Add HTML footer.                                                 ##
##                                                                  ##
######################################################################
######################################################################

def add_html_footer(response):
    response.append("</tbody></table></body></html>")


######################################################################
######################################################################
##                                                                  ##
## Build response.                                                  ##
##                                                                  ##
######################################################################
######################################################################

def build_response():
    # Get the current time.
    now = time.time()

    try:
        for nattempts in range(0, 3):
            # Send command to the sniffer via named pipe.
            pipe = open(PIPE_FILENAME, "wb")
            pipe.write("\x01")
            pipe.close()

            time.sleep(0.05)

            try:
                if os.path.getmtime(CONNECTIONS_FILENAME) + 5 >= now:
                    break
            except:
                pass
        else:
            # The maximum number of attempts has been reached.
            return [ERROR_PAGE]
    except:
        # Error.
        return [ERROR_PAGE]

    # Open file for reading.
    try:
        f = open(CONNECTIONS_FILENAME, "rb")
    except:
        # Error opening file.
        return [ERROR_PAGE]

    # List of connections for the current source IP.
    connections = []

    destips = []

    nsrcip = 0

    prev_srcip = ""
    prev_destip = ""

    nlines = 0
    offset = 0

    response = []
    add_html_header(response)

    # Read first chunk.
    lines = f.readlines(READ_BUFFER_SIZE)
    while lines:
        for line in lines:
            linelen = len(line)

            # If the last character is '\n'...
            if line[-1] == '\n':
                tokens = line[:-1].split("\t")
            else:
                tokens = line.split("\t")

            # Format:
            # ip1:port1 \t [->|<-] \t ip2:port2 \t <creation> \t <timestamp> \t <uploaded> \t <downloaded> \n
            # -----------------------------------------------------------------------------------------------
            #  token 0     token 1     token 2      token 3        token 4       token 5        token 6

            # If the number of tokens is different than 7...
            if len(tokens) != 7:
                continue

            # Get source.
            src = tokens[0].split(":")
            if len(src) != 2:
                continue

            # Get destination.
            dest = tokens[2].split(":")
            if len(dest) != 2:
                continue

            srcip = src[0]
            destip = dest[0]

            if srcip != prev_srcip:
                # If the connection list is not empty...
                if len(connections) > 0:
                    add_connections(response, nsrcip, prev_srcip, connections, destips)

                    # Clear the connection list.
                    del connections[:]

                    del destips[:]

                    nsrcip = nsrcip + 1

                destips.append([destip, 1])

                prev_srcip = srcip
                prev_destip = destip
            elif destip != prev_destip:
                prev_destip = destip

                destips.append([destip, 1])
            else:
                # Increment the last count.
                destips[-1][1] = destips[-1][1] + 1

            # Add connection to the list of connections
            # for the current source IP.
            connections.append(tokens)

            offset = offset + linelen

            nlines = nlines + 1
            if nlines == MAX_LINES:
                break

        # Read next chunk.
        lines = f.readlines(READ_BUFFER_SIZE)

    # Close the file.
    f.close()

    if len(connections) > 0:
        add_connections(response, nsrcip, prev_srcip, connections, destips)
    elif nlines == 0:
        response.append("<tr><td class=\"no_connections\" colspan=\"7\">\
No connections</td></tr>")

    add_html_footer(response)

    return response


######################################################################
######################################################################
##                                                                  ##
## connections.                                                     ##
##                                                                  ##
######################################################################
######################################################################

def connections(start_response):
    start_response("200 OK", [("Content-Type", "text/html")])
    return build_response()
