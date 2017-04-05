set (LILLYDAP_SRC
	derbuf.c
	dermsg.c
	mem.c
	msgop.c
	opswi.c
	queue.c
	rfc1823.c
)

ecm_gperf_generate(${CMAKE_CURRENT_SOURCE_DIR}/msgop.gperf msgop.tab LILLYDAP_SRC
	GENERATION_FLAGS "-m 10")

include_directories (${CMAKE_CURRENT_BINARY_DIR})  # For msgop.tab which was output

# Build LillyDAP both shared and static.
add_library (lillydapShared SHARED ${LILLYDAP_SRC})
set_target_properties (
	lillydapShared
	PROPERTIES OUTPUT_NAME lillydap)

add_library (lillydapStatic STATIC ${LILLYDAP_SRC})
set_target_properties (
	lillydapStatic
	PROPERTIES OUTPUT_NAME lillydap
)

if (NOT ${BUILD_SINGLE_THREADED})
	add_dependencies (lillydapStatic openpa-makefile)
	add_dependencies (lillydapShared openpa-makefile)
endif()

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
