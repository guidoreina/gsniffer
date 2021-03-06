#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <signal.h>
#include "net/sniffer.h"

static void signal_handler(int nsignal);
static void handle_alarm(int nsignal);

net::sniffer gsniffer;

int main(int argc, char** argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <interface> <log-directory>\n", argv[0]);
		return -1;
	}

	if (!gsniffer.create(argv[1], argv[2], 32 * 1024 * 1024)) {
		fprintf(stderr, "Couldn't create sniffer.\n");
		return -1;
	}

	struct sigaction act;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = signal_handler;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);

	act.sa_handler = handle_alarm;
	sigaction(SIGALRM, &act, NULL);

	struct itimerval value;
	value.it_interval.tv_sec = 5;
	value.it_interval.tv_usec = 0;
	value.it_value.tv_sec = 5;
	value.it_value.tv_usec = 0;
	if (setitimer(ITIMER_REAL, &value, NULL) < 0) {
		fprintf(stderr, "Couldn't set real-time alarm.\n");
		return -1;
	}

	gsniffer.start();

	return 0;
}

void signal_handler(int nsignal)
{
	fprintf(stderr, "Signal received...\n");

	gsniffer.stop();
}

void handle_alarm(int nsignal)
{
	gsniffer.on_alarm();
}
