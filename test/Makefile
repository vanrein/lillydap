TARGETS=lillygetprint

lillygetprint_OBJS = lillygetprint.o sillymem.o
lillygetprint_LIBS = ../lib/mem.o ../lib/derbuf.o ../lib/dermsg.o ../lib/msgop.o ../lib/queue.o /usr/local/src/quick-der/lib/der_header.o /usr/local/src/quick-der/lib/der_unpack.o /usr/local/src/quick-der/lib/der_pack.o /usr/local/src/quick-der/lib/der_skipenter.o /usr/local/src/quick-der/lib/der_iterate.o

OBJS = $(lillygetprint_OBJS)

CFLAGS=-c -O0 -ggdb3 -DDEBUG
LDFLAGS=-O0 -ggdb3

all: $(TARGETS)

clean:
	rm -f $(TARGETS) $(OBJS)

anew: clean all

lillygetprint: $(lillygetprint_OBJS)
	gcc $(LDFLAGS) -o "$@" $(lillygetprint_OBJS) $(lillygetprint_LIBS)

lillygetprint.o: lillygetprint.c
	gcc $(CFLAGS) -I ../include -o "$@" "$<"

sillymem.o: ../lib/sillymem.c
	gcc $(CFLAGS) -DUSE_SILLYMEM -I ../include -o "$@" "$<"
