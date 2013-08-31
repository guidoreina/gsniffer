CC=g++
CXXFLAGS=-g -Wall -pedantic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -Wno-format -Wno-long-long -I.
CXXFLAGS+=-DHAVE_PREAD
# CXXFLAGS+=-DDEBUG

LDFLAGS=
LIBS=

MAKEDEPEND=${CC} -MM
PROGRAM=sniffer

OBJS =	constants/months_and_days.o string/buffer.o fs/file.o util/number.o util/ranges.o \
	net/connection.o net/connection_list.o net/packet_processor.o net/sniffer.o \
	net/internet/http/analyzer.o net/internet/http/logger.o net/internet/http/date.o net/internet/http/headers.o \
	main.o

DEPS:= ${OBJS:%.o=%.d}

all: $(PROGRAM)

${PROGRAM}: ${OBJS}
	${CC} ${CXXFLAGS} ${LDFLAGS} ${OBJS} ${LIBS} -o $@

clean:
	rm -f ${PROGRAM} ${OBJS} ${OBJS} ${DEPS}

${OBJS} ${DEPS} ${PROGRAM} : Makefile

.PHONY : all clean

%.d : %.cpp
	${MAKEDEPEND} ${CXXFLAGS} $< -MT ${@:%.d=%.o} > $@

%.o : %.cpp
	${CC} ${CXXFLAGS} -c -o $@ $<

-include ${DEPS}
