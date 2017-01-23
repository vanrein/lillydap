TARGETS=lillydump stampede #lillypass

lillydump_OBJS = lillydump.o sillymem.o
lillydump_LIBS = ../lib/mem.o ../lib/derbuf.o ../lib/dermsg.o ../lib/msgop.o ../lib/opswi.o ../lib/queue.o /usr/local/src/quick-der/lib/der_header.o /usr/local/src/quick-der/lib/der_unpack.o /usr/local/src/quick-der/lib/der_pack.o /usr/local/src/quick-der/lib/der_skipenter.o
#/usr/local/src/quick-der/lib/der_iterate.o

stampede_OBJS = stampede.o sillymem.o
stampede_LIBS = ../lib/mem.o ../lib/queue.o -lpthread

lillypass_OBJS = lillypass.o sillymem.o
lillypass_LIBS = ../lib/mem.o ../lib/derbuf.o ../lib/dermsg.o ../lib/msgop.o ../lib/opswi.o ../lib/queue.o /usr/local/src/quick-der/lib/der_header.o /usr/local/src/quick-der/lib/der_unpack.o /usr/local/src/quick-der/lib/der_pack.o /usr/local/src/quick-der/lib/der_skipenter.o

OBJS = $(lillydump_OBJS) $(lillypass_OBJS)

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

stampede: $(stampede_OBJS)
	gcc $(LDFLAGS) -o "$@" $(stampede_OBJS) $(stampede_LIBS)

stampede.o: stampede.c
	gcc -pthread $(CFLAGS) -I ../include -I ../import/openpa-1.0.4/src -o "$@" "$<"

lillypass: $(lillypass_OBJS)
	gcc $(LDFLAGS) -o "$@" $(lillypass_OBJS) $(lillypass_LIBS)

lillypass.o: lillypass.c
	gcc $(CFLAGS) -I ../include -o "$@" "$<"

sillymem.o: ../lib/sillymem.c
	gcc $(CFLAGS) -DUSE_SILLYMEM -I ../include -o "$@" "$<"

