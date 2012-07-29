CC=g++
CXXFLAGS=-g -Wall -pedantic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -Wno-format -Wno-long-long -I.
# CXXFLAGS+=-DDEBUG

LDFLAGS=
LIBS=

MAKEDEPEND=${CC} -MM
PROGRAM=sniffer

OBJS =	connection_list.o analyzer.o sniffer.o main.o

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
