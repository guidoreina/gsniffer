gsniffer
========

Packet sniffer for Linux.

Running:
The program receives as argument the interface name to which it should bind to.

Introduction:
gsniffer reads network packets using PACKET_MMAP and builds a list of TCP connections.

At the moment, gsniffer only analyzes HTTP traffic and prints on the display the
web pages which are being visited.
