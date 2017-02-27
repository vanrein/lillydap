add_custom_command (
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/openpa-1.0.4/configure
	COMMAND tar -xzvf ${CMAKE_SOURCE_DIR}/import/openpa-1.0.4.tar.gz
	COMMENT "Unpack OpenPA to make its include files avaliable"
	VERBATIM
	SOURCES ${CMAKE_SOURCE_DIR}/import/openpa-1.0.4.tar.gz
)
add_custom_command (
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/openpa-1.0.4/Makefile
	COMMAND ./configure
	COMMENT "Configure OpenPA to unleash its include files"
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/openpa-1.0.4
	VERBATIM
)
add_custom_target (openpa-configure DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/openpa-1.0.4/configure)
add_custom_target (openpa-makefile DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/openpa-1.0.4/Makefile)
add_dependencies (openpa-makefile openpa-configure)

set (OPENPA_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/openpa-1.0.4/src)
include_directories (${OPENPA_INCLUDE_DIRS})
# set_directory_properties(PROPERTIES OPENPA_INCLUDE_DIRS ${OPENPA_INCLUDE_DIRS})

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/openpa-1.0.4/src/opa_primitives.h
	DESTINATION include/lillydap)
