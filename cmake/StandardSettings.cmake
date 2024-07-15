#
# Compiler options
#

option(${PROJECT_NAME}_WARNINGS_AS_ERRORS "Treat compiler warnings as errors." ${${PROJECT_NAME}_IS_TOPLEVEL_PROJECT})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BUILD_SHARED_LIBS "Build libraries as shared libraries" ON)

# This is mainly useful for system packaging to create libquic.so.x.y instead of just libquic.so:
option(${PROJECT_NAME}_VERSION_SO "Add the project major/minor version into the shared library filename" OFF)

#
# Unit testing
#
# Currently supporting: Catch2.

option(${PROJECT_NAME}_ENABLE_UNIT_TESTING "Enable unit tests for the projects (from the `test` subfolder)." ${${PROJECT_NAME}_IS_TOPLEVEL_PROJECT})

#
# Crypto Library
#
option(${PROJECT_NAME}_ENABLE_CRYPTO_LIBRARY "Use the internal crypto library" ON)

#
# Static analyzers
#
# Currently supporting: Clang-Tidy, Cppcheck.

option(${PROJECT_NAME}_ENABLE_CLANG_TIDY "Enable static analysis with Clang-Tidy." OFF)
option(${PROJECT_NAME}_ENABLE_CPPCHECK "Enable static analysis with Cppcheck." OFF)

#
# Miscelanious options
#

option(${PROJECT_NAME}_VERBOSE_OUTPUT "Enable verbose output, allowing for a better understanding of each step taken." ON)

option(${PROJECT_NAME}_ENABLE_LTO "Enable Interprocedural Optimization, aka Link Time Optimization (LTO)." ON)
if(${PROJECT_NAME}_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT result OUTPUT output)
  if(result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(SEND_ERROR "IPO is not supported: ${output}.")
  endif()
endif()


option(${PROJECT_NAME}_ENABLE_CCACHE "Enable the usage of Ccache, in order to speed up rebuild times." ON)
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()

option(${PROJECT_NAME}_ENABLE_ASAN "Enable Address Sanitize to detect memory error." OFF)
if(${PROJECT_NAME}_ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()


if (${PROJECT_NAME}_IS_TOPLEVEL_PROJECT OR BUILD_SHARED_LIBS)
    set(${PROJECT_NAME}_INSTALL_DEFAULT ON)
else()
    set(${PROJECT_NAME}_INSTALL_DEFAULT OFF)
endif()
option(${PROJECT_NAME}_INSTALL "Add libraries/headers to cmake install target; defaults to ON if BUILD_SHARED_LIBS is enabled or we are the top-level project"
    ${${PROJECT_NAME}_IS_TOPLEVEL_PROJECT})
