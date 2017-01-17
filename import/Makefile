all: openpa-1.0.4/src/config.h

openpa-1.0.4/src/config.h: openpa-1.0.4
	cd openpa-1.0.4 ; ./configure ; cd ..

openpa-1.0.4: openpa-1.0.4.tar.gz
	tar -xzvf "$<"
