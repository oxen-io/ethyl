cmake_minimum_required(VERSION 3.15)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#
# Project details
#

# When bumping the version, bump the 3rd version for source-only changes (i.e. no API changes in
# headers), and the 2nd version if anything in the headers change.
project(
  ethyl
  VERSION 0.1.0
  LANGUAGES C CXX
)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(${PROJECT_NAME}_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(${PROJECT_NAME}_IS_TOPLEVEL_PROJECT FALSE)
endif()

#
# Set project options
#
include(cmake/StandardSettings.cmake)
include(cmake/StaticAnalyzers.cmake)
include(cmake/Utils.cmake)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()
message(STATUS "Started CMake for ${PROJECT_NAME} v${PROJECT_VERSION}...\n")

if (UNIX)
    add_compile_options("$<$<CONFIG:DEBUG>:-D_DEBUG>")    #this will allow to use same _DEBUG macro available in both Linux as well as Windows - MSCV environment. Easy to put Debug specific code.
endif (UNIX)


#
# Prevent building in the source directory
#

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there.\n")
endif()

#
# Create library, setup header and source files
#

# Find all headers and implementation files
include(cmake/SourcesAndHeaders.cmake)
add_subdirectory(external)
add_subdirectory(src/ethyl-keccak)

add_library(
    ${PROJECT_NAME}
    ${sources}
)

#
# Unit testing setup
#
if(${PROJECT_NAME}_ENABLE_UNIT_TESTING)
    enable_testing()
    message(STATUS "Build unit tests for the project. Tests should always be found in the test folder\n")
    add_subdirectory(test)
endif()

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/${CMAKE_BUILD_TYPE}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/${CMAKE_BUILD_TYPE}"
)
if(${PROJECT_NAME}_VERSION_SO)
  set_target_properties(
      ${PROJECT_NAME}
      PROPERTIES
      SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
endif()


message(STATUS "Added all header and implementation files.\n")

#
# Set the project standard and warnings
#

include(cmake/CompilerWarnings.cmake)
set_project_warnings(${PROJECT_NAME})

verbose_message("Applied compiler warnings.\n")

#
# Model project dependencies
#

# Identify and link with the specific "packages" the project uses
target_link_libraries(
  ${PROJECT_NAME}
  PUBLIC
    nlohmann_json::nlohmann_json
    oxenc::oxenc
    secp256k1
  PRIVATE
    cpr::cpr
    oxen::logging
    ethyl-keccak
    gmp
    gmpxx
)

verbose_message("Successfully added all dependencies and linked against them.")

#
# Set the build/user include directories
#

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
message(STATUS "Finished setting up include directories.")


#
# Format the project using the `clang-format` target (i.e: cmake --build build --target clang-format)
#
add_clang_format_target()

#
# Add version header
#

configure_file(
  ${CMAKE_CURRENT_LIST_DIR}/cmake/version.hpp.in
  include/${PROJECT_NAME_LOWERCASE}/version.hpp
  @ONLY
)


message(STATUS "Finished building requirements for installing the package.\n")

if(${PROJECT_NAME}_INSTALL)
    include(GNUInstallDirs)

    install(
        DIRECTORY include/ethyl
        TYPE INCLUDE
        FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h")

    install(
        TARGETS ${PROJECT_NAME}
        EXPORT ethylConfig
        DESTINATION ${CMAKE_INSTALL_LIBDIR})

    configure_file(libethyl.pc.in libethyl.pc @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/libethyl.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
