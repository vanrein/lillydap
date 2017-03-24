#
# CMakeLists.txt for LillyDAP
#

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)
project ("LillyDAP" C)

set (CMAKE_MACOSX_RPATH 0)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

include (MacroEnsureOutOfSourceBuild)
include (MacroAddUninstallTarget)
include (MacroGitVersionInfo)
include (MacroCreateConfigFiles)

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

find_package (Quick-DER REQUIRED)

#
# Version Information
#
get_version_from_git (LillyDAP 0.4.0)

#
# Building
#

include_directories (include)
include_directories (${Quick-DER_INCLUDE_DIRS})
include_directories (import/openpa-1.0.4/src)

if (${BUILD_SINGLE_THREADED})
	add_definitions (-DCONFIG_SINGLE_THREADED)
else ()
	add_subdirectory (import)
	get_directory_property (OPENPA_INCLUDE_DIRS DIRECTORY import DEFINITION OPENPA_INCLUDE_DIRS)
	include_directories (${OPENPA_INCLUDE_DIRS})
endif ()


add_subdirectory (lib)
add_subdirectory (python)

#
# TESTS
#

enable_testing ()
add_subdirectory (test)

#
# INSTALLING
#

install (
	DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/lillydap
	DESTINATION include
	FILES_MATCHING PATTERN "*.h"
)


#
# PACKAGING
#

set (CPACK_PACKAGE_VERSION_MAJOR ${LillyDAP_VERSION_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${LillyDAP_VERSION_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${LillyDAP_VERSION_PATCHLEVEL})

set (CPACK_BUNDLE_NAME "LillyDAP")
set (CPACK_PACKAGE_CONTACT "Rick van Rein <rick@openfortress.nl>")
set (CPACK_PACKAGE_VENDOR "ARPA2.net")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "LDAP devkit, turns LDAP operations into functions/callbacks")
set (CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_SOURCE_DIR}/README.MD)
set (CPACK_GENERATOR DEB RPM)
set (CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

include (CPack)

create_config_files (LillyDAP)
#
# END OF CMakeLists.txt
#
