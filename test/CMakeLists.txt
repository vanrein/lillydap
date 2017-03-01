set(SILLY_SRC ../lib/sillymem.c)

add_executable (
	lillydump.test
	lillydump.c
	${SILLY_SRC}
)
set_target_properties (
	lillydump.test
	PROPERTIES COMPILE_DEFINITIONS USE_SILLYMEM
)
target_link_libraries (
	lillydump.test
	lillydapStatic
	${Quick-DER_LIBRARIES}
)

if (NOT ${BUILD_SINGLE_THREADED})
	add_executable (
		stampede.test
		stampede.c
		${SILLY_SRC}
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
		${Quick-DER_LIBRARIES}
		${CMAKE_THREAD_LIBS_INIT}	-lpthread
	)
endif()

add_executable (
	lillypass.test
	lillypass.c
	${SILLY_SRC}
)
set_target_properties (
	lillypass.test
	PROPERTIES COMPILE_DEFINITIONS USE_SILLYMEM
)
target_link_libraries (
	lillypass.test
	lillydapStatic
	${Quick-DER_LIBRARIES}
	#ORIG# ${Quick-DER_LIBRARIES}
)

file (GLOB netpkgs ldap/*.bin)

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
	foreach (level 0 1 2)  #TODO# 3 4
		add_test (
			NAME lillypass-level${level}-netpkg-${netpkgname}
			COMMAND lillypass.test ${level} ${netpkg}
		)
	endforeach()
endforeach()

