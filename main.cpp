#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "sniffer.h"

static void signal_handler(int nsignal);

sniffer sniffer;

int main(int argc, char** argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <interface>\n");
		return -1;
	}

	if (!sniffer.create(argv[1], 32 * 1024 * 1024)) {
		fprintf(stderr, "Couldn't create sniffer.\n");
		return -1;
	}

	struct sigaction act;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = signal_handler;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);

	sniffer.start();

	return 0;
}

void signal_handler(int nsignal)
{
	fprintf(stderr, "Signal received...\n");

	sniffer.stop();
}
