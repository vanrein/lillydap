# Installing LillyDAP

> *You should be able to get started with LillyDAP quite easily.*


## Requirements

Runtime requirements:

  * [Quick DER](http://github.com/vanrein/quick-der)
  * We may add `libpcre` later, for optional attrtype syntax checking

Building requirements:

  * C compiler (we test with `gcc`)
  * [CMake](https://cmake.org)

Packaging requirements:

  * `rpmbuild` to build an RPM package for RedHat, SuSe, Fedora
  * `dpkg-buildpackage` to build a DEB package for Debian, Ubuntu, Mint
  * `makensis` to build a Nullsoft Installer for Windows

By default, both the generators `RPM` and `DEB` are used.
You can select what packages to provide by selecting a generator in the
CPack command, for instance

    cpack -G NSIS


## Configuration Choices

We use atomic operations to achieve lock-free concurrency.  If you are in a
single-threaded environment, you do not need those.  You will be able to set
the `BUILD_SINGLE_THREADED` option to replace atomic operations with simpler
ones.  You will break the lock-free concurrency model if you use
multi-threading on any such setups.

The major and minor version will be derived from Git automatically.  The
same goes for the patch level, which may however be locally overridden by
package makers if they so desire.  The one exception is when Git has local
changes; in that case, the patch level must be supplied by the user; a
warning will be emitted from CMake and the string is set to `local-` and
a timestamp in `YYYYMMDD-hhmmss` notation.

To make configuration changes, use either `ccmake` or `cmake-gui` instead
of `cmake` when building.  A first pass gives you the option that you can
override.  Or, to automate this choice, you could use

    cmake -D BUILD_SINGLE_THREADED:BOOL=ON ..


## Building, Testing and Packaging

We advise out-of-source builds, even though we have a few items on our
TODO list that require preparations inside the code tree for now.

    cd lillydap
    mkdir build
    cd build

In this build directory, configure using defaults, or use a variant as
described under configuration.  You need to reference the source tree
relative to the build directory, so `..` after the preparation above,

    cmake ..

Then proceed to building,

    make

You can now run the package's tests,

    ctest

Finally, you can create packages, using `DEB` and `RPM` generators by
default, using

    cpack

We will work to integrate LillyDAP with the [MXE](http://mxe.cc)
cross-building environment for Windows.  You will then be able to
cross-package using

    cpack -G NSIS

