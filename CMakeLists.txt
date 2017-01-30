#
# CMakeLists.txt for LillyDAP
#

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)
project ("LillyDAP" C)

set (CMAKE_MACOSX_RPATH 0)

option (DEBUG
	"Produce verbose output"
	OFF)

option (BUILD_SINGLE_THREADED
	"Build without atomic operations because LillyDAP runs in one thread"
	OFF)


#
# Dependencies
#

if (NOT ${BUILD_SINGLE_THREADED})
	find_package (Threads REQUIRED)
endif()

find_package (PkgConfig)
pkg_search_module (
	QuickDER REQUIRED
	quick-der quickder Quick-DER QuickDER
)


#
# Version Information
#

find_package (Git)

exec_program (
		${GIT_EXECUTABLE}
		ARGS diff --quiet
		RETURN_VALUE GIT_HAVE_CHANGES
)

exec_program (
		${GIT_EXECUTABLE}
		ARGS describe --tags --match 'version-*.*-*'
		OUTPUT_VARIABLE GIT_VERSION_INFO
)

string (
	REGEX REPLACE "^version-([1-9][0-9]*|0)[.]([1-9][0-9]*|0)-(.*)$"
	"\\1"
	GIT_VERSION_MAJOR
	${GIT_VERSION_INFO}
)

string (
	REGEX REPLACE "^version-([1-9][0-9]*|0)[.]([1-9][0-9]*|0)-(.*)$"
	"\\2"
	GIT_VERSION_MINOR
	${GIT_VERSION_INFO}
)

if (GIT_HAVE_CHANGES EQUAL 0)

	string (
		REGEX REPLACE "^version-([1-9][0-9]*|0)[.]([1-9][0-9]*|0)-(.*)$"
		"\\3"
		GIT_VERSION_PATCHLEVEL
		${GIT_VERSION_INFO}
	)

	set (
		USER_SUPPLIED_PATCHLEVEL
		"${GIT_VERSION_PATCHLEVEL}"
		CACHE STRING "User-override for patch level under ${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}"
	)

else()

	exec_program (
		date
		ARGS '+%Y%m%d-%H%M%S'
		OUTPUT_VARIABLE GIT_CHANGES_TIMESTAMP
	)
	set (GIT_VERSION_PATCHLEVEL "local-${GIT_CHANGES_TIMESTAMP}")
	message (WARNING "Git reports local changes, fixing patch level to local-${GIT_CHANGES_TIMESTAMP}")

	unset (USER_SUPPLIED_PATCHLEVEL CACHE)

endif()


#
# Building
#

if (${BUILD_SINGLE_THREADED})
	add_definitions (-DCONFIG_SINGLE_THREADED)
endif ()

include_directories (include)
include_directories (QuickDER_INCLUDEDIR)
include_directories (import/openpa-1.0.4/src)

add_library (
	lillydapShared SHARED
	lib/derbuf.c
	lib/dermsg.c
	lib/mem.c
	lib/msgop.c
	lib/opswi.c
	lib/queue.c
	lib/rfc1823.c
)
set_target_properties (
	lillydapShared
	PROPERTIES OUTPUT_NAME lillydap)

add_library (
	lillydapStatic STATIC
	lib/derbuf.c
	lib/dermsg.c
	lib/mem.c
	lib/msgop.c
	lib/opswi.c
	lib/queue.c
	lib/rfc1823.c
)
set_target_properties (
	lillydapStatic
	PROPERTIES OUTPUT_NAME lillydap
)

add_custom_target (
	openpa-dir
	COMMAND tar -xzvf openpa-1.0.4.tar.gz
	COMMENT "Unpack OpenPA to make its include files avaliable"
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/import
	VERBATIM
)
add_custom_target (
	openpa
	COMMAND ./configure
	COMMENT "Configure OpenPA to unleash its include files"
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/import/openpa-1.0.4
	VERBATIM
	SOURCES import/openpa-1.0.4.tar.gz
)
add_dependencies (openpa openpa-dir)

add_custom_target (
	msgop.tab
	COMMAND gperf -m 10 msgop.gperf --output-file=msgop.tab
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
	COMMENT "Run gperf to produce opcode table"
	VERBATIM
	SOURCES lib/msgop.gperf
)

add_dependencies (lillydapStatic msgop.tab)
add_dependencies (lillydapShared msgop.tab)
if (NOT ${BUILD_SINGLE_THREADED})
	add_dependencies (lillydapStatic openpa)
	add_dependencies (lillydapShared openpa)
endif()

configure_file (
	contrib/pkgconfig/lillydap.pc.in
	${PROJECT_BINARY_DIR}/lillydap.pc
	@ONLY
)


#
# TESTS
#

enable_testing ()

add_executable (
	lillydump.test
	test/lillydump.c
	lib/mem.c
	lib/derbuf.c
	lib/dermsg.c
	lib/msgop.c
	lib/opswi.c
	lib/sillymem.c
)
set_target_properties (
	lillydump.test
	PROPERTIES COMPILE_DEFINITIONS USE_SILLYMEM
)
target_link_libraries (
	lillydump.test
	lillydapStatic
	${QuickDER_LDFLAGS}	#TODO# Proper form, _LDFLAGS???
)

if (NOT ${BUILD_SINGLE_THREADED})
	add_executable (
		stampede.test
		test/stampede.c
		lib/mem.c
		lib/queue.c
		lib/sillymem.c
	)
	set_target_properties (
		stampede.test
		PROPERTIES COMPILE_DEFINITIONS USE_SILLYMEM
	)
	#TODO# Really -pthread, literally?!?
	if(THREADS_HAVE_PTHREAD_ARG)
		target_compile_options(stampede.test "-pthread")
	endif()
	target_link_libraries (
		stampede.test
		lillydapStatic
		${QuickDER_LDFLAGS}	#TODO# Proper form, _LDFLAGS???
		${CMAKE_THREAD_LIBS_INIT}	-lpthread
	)
endif()

add_executable (
	lillypass.test
	test/lillypass.c
	lib/mem.c
	lib/derbuf.c
	lib/dermsg.c
	lib/msgop.c
	lib/opswi.c
	lib/sillymem.c
	lib/queue.c
)
set_target_properties (
	lillypass.test
	PROPERTIES COMPILE_DEFINITIONS USE_SILLYMEM
)
target_link_libraries (
	lillypass.test
	lillydapStatic
	${QuickDER_LDFLAGS}	#TODO# Proper form, _LDFLAGS???
)

file (GLOB netpkgs test/ldap/*.bin)

#TODO# Test that output matches expectations
foreach (netpkg ${netpkgs})
	get_filename_component (netpkgname ${netpkg} NAME)
	add_test (
		NAME lillydump-netpkg-${netpkgname}
		COMMAND lillydump.test ${netpkg}
	)
endforeach()

#TODO# Test that all serials exist, in proper order, for each threadid
if (NOT ${BUILD_SINGLE_THREADED})
	# This is a test of lock-free concurrency, useless when single-threaded
	add_test (
		NAME stampede.test
		COMMAND stampede.test 250
	)
endif()

#TODO# Test that the output matches expectations
foreach (netpkg ${netpkgs})
	get_filename_component (netpkgname ${netpkg} NAME)
	foreach (level 0 1 2 3)  #TODO# 4
		add_test (
			NAME lillypass-level${level}-netpkg-${netpkgname}
			COMMAND lillypass.test ${level} ${netpkg}
		)
	endforeach()
endforeach()


#
# INSTALLING
#

install (
	TARGETS lillydapShared
	LIBRARY DESTINATION lib
	PUBLIC_HEADER DESTINATION include/lillydap
)

install (
	TARGETS lillydapStatic
	ARCHIVE DESTINATION lib
	PUBLIC_HEADER DESTINATION include/lillydap
)

install (
	DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/lillydap
	DESTINATION include
	FILES_MATCHING PATTERN "*.h"
)

install (
	FILES ${PROJECT_BINARY_DIR}/lillydap.pc
	DESTINATION lib/pkgconfig
)


#
# PACKAGING
#

set (CPACK_PACKAGE_VERSION_MAJOR ${GIT_VERSION_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${GIT_VERSION_MINOR})
if (GIT_HAVE_CHANGES EQUAL 0)
	set (CPACK_PACKAGE_VERSION_PATCH ${USER_SUPPLIED_PATCHLEVEL})
else()
	set (CPACK_PACKAGE_VERSION_PATCH "local-${GIT_CHANGES_TIMESTAMP}")
endif()

set (CPACK_BUNDLE_NAME "LillyDAP")
set (CPACK_PACKAGE_CONTACT "Rick van Rein <rick@openfortress.nl>")
set (CPACK_PACKAGE_VENDOR "ARPA2.net")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "LDAP devkit, turns LDAP operations into functions/callbacks")
set (CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_SOURCE_DIR}/README.MD)
set (CPACK_GENERATOR DEB RPM)
set (CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

include (CPack)


#
# END OF CMakeLists.txt
#
