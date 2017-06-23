# LillyDAP
#
# This Makefile is just a stub: it invokes CMake, which in turn
# generates Makefiles, and then uses those to make the project.
#
# Useful Make parameters at this level are:
#	PREFIX=/usr/local
#
# For anything else, do this:
#
#	make configure                 # Basic configure
#	( cd build ; ccmake )          # CMake GUI for build configuration
#	( cd build ; make install )    # Build and install
#
PREFIX ?= /usr/local

all: compile

build-dir:
	@mkdir -p build

configure: _configure build-dir build/CMakeCache.txt

_configure:
	@rm -f build/CMakeCache.txt

build/CMakeCache.txt:
	( cd build && cmake .. -DCMAKE_INSTALL_PREFIX=$(PREFIX) )

compile: build-dir build/CMakeCache.txt
	( cd build && $(MAKE) )

install: build-dir
	( cd build && $(MAKE) install )

test: build-dir
	( cd build && $(MAKE) test )

uninstall: build-dir
	( cd build && $(MAKE) uninstall )

clean:
	rm -rf build/

package: compile
	( cd build && $(MAKE) package )

