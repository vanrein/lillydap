TARGETS=lillydump

lillydump_OBJS = lillydump.o sillymem.o
lillydump_LIBS = ../lib/mem.o ../lib/derbuf.o ../lib/dermsg.o ../lib/msgop.o ../lib/opswi.o ../lib/queue.o /usr/local/src/quick-der/lib/der_header.o /usr/local/src/quick-der/lib/der_unpack.o /usr/local/src/quick-der/lib/der_pack.o /usr/local/src/quick-der/lib/der_skipenter.o
#/usr/local/src/quick-der/lib/der_iterate.o

OBJS = $(lillydump_OBJS)

CFLAGS=-c -O0 -ggdb3 -DDEBUG
LDFLAGS=-O0 -ggdb3

all: $(TARGETS)

clean:
	rm -f $(TARGETS) $(OBJS)

anew: clean all

lillydump: $(lillydump_OBJS)
	gcc $(LDFLAGS) -o "$@" $(lillydump_OBJS) $(lillydump_LIBS)

lillydump.o: lillydump.c
	gcc $(CFLAGS) -I ../include -o "$@" "$<"

sillymem.o: ../lib/sillymem.c
	gcc $(CFLAGS) -DUSE_SILLYMEM -I ../include -o "$@" "$<"
