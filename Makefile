CFLAGS=-g -I.

OBJS=tcptest.o

tcptest:${OBJS}
	gcc -o tcptest ${OBJS} -lc -static

install:

all:tcptest

