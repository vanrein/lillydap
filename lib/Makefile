TARGETS=liblillydap.a liblillydap.so libsillymem.a libsillymem.so

SUBTARGETS=msgop.tab mem.o queue.o sillymem.o derbuf.o dermsg.o msgop.o opswi.o

# CFLAGS=-Os -ggdb3 -DDEBUG -I ../import/openpa-1.0.4/src
CFLAGS=-O0 -ggdb3 -DDEBUG -I ../import/openpa-1.0.4/src

all: $(SUBTARGETS)

clean:
	rm -f $(SUBTARGETS) $(TARGETS)

anew: clean all

derbuf.o: derbuf.c
	gcc $(CFLAGS) -c -I ../include -o "$@" "$<"

dermsg.o: dermsg.c
	gcc $(CFLAGS) -c -I ../include -o "$@" "$<"

sillymem.o: sillymem.c
	gcc $(CFLAGS) -c -I ../include -o "$@" "$<"

msgop.o: msgop.c msgop.tab
	gcc $(CFLAGS) -c -I ../include -o "$@" "$<"

opswi.o: opswi.c
	gcc $(CFLAGS) -c -I ../include -o "$@" "$<"

mem.o: mem.c
	gcc $(CFLAGS) -c -I ../include -o "$@" "$<"

queue.o: queue.c
	gcc $(CFLAGS) -c -I ../include -o "$@" "$<"

msgop.tab: msgop.gperf
	gperf -m 10 "$<" --output-file="$@"

