# Executables that use Sillymem can be added through the
# macro add_executable_silly(), which adds the necessary
# definitions and extra sources.
set(SILLY_SRC ../lib/sillymem.c)
macro(add_executable_silly _name)
	add_executable(${_name} ${ARGN} ${SILLY_SRC})
	set_target_properties (
		${_name}
		PROPERTIES COMPILE_DEFINITIONS USE_SILLYMEM
	)
endmacro()

add_executable_silly (
	lillydump.test
	lillydump.c
)
target_link_libraries (
	lillydump.test
	lillydapStatic
	${Quick-DER_STATIC_LIBRARIES}
)

if (NOT ${BUILD_SINGLE_THREADED})
	add_executable_silly (
		stampede.test
		stampede.c
	)

	#TODO# Really -pthread, literally?!?
	if(THREADS_HAVE_PTHREAD_ARG)
		target_compile_options(stampede.test "-pthread")
	endif()
	target_link_libraries (
		stampede.test
		lillydapStatic
		${Quick-DER_STATIC_LIBRARIES}
		${CMAKE_THREAD_LIBS_INIT}	-lpthread
	)
endif()

add_executable_silly (
	lillypass.test
	lillypass.c
)
target_link_libraries (
	lillypass.test
	lillydapStatic
	${Quick-DER_STATIC_LIBRARIES}
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

# Not so much a test as a standalone test-helper
add_executable(ldap-mitm ldap-mitm.c)
