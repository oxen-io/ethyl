#
# CPR
#
if(NOT TARGET cpr)
    set(CPR_USE_SYSTEM_CURL ON CACHE BOOL "")
    add_subdirectory(cpr)
endif()

#
# SECP256k1
#
if(NOT TARGET secp256k1)
    set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
    set(SECP256K1_VALGRIND OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    add_subdirectory(secp256k1)
endif()

#
# Catch2
#
if(NOT TARGET Catch2)
    add_subdirectory(Catch2)
endif()

#
# rlpvalue is built using autotools
#
include(ExternalProject)
set(RLP_DIR         ${CMAKE_CURRENT_SOURCE_DIR}/rlpvalue)
set(RLP_BIN         ${CMAKE_CURRENT_BINARY_DIR}/librlpvalue)
set(RLP_STATIC_LIB  ${RLP_BIN}/lib/librlpvalue.a)
set(RLP_INCLUDES    ${RLP_BIN}/include)
file(MAKE_DIRECTORY ${RLP_INCLUDES})

# NOTE: rlpvalue includes a sub-project, univalue which it configures from the
# top level script. Passing in the `--prefix` at the top-level does not
# propagate down to the bottom level causing `make install` to install to the
# system level prefix.
#
# We override this by specifying prefix at the last step ensuring that both
# `rlpvalue` and `univalue` are installed to the same prefix.
ExternalProject_Add(
    librlpvalue
    PREFIX            ${RLP_BIN}
    SOURCE_DIR        ${RLP_DIR}
    DOWNLOAD_COMMAND  cd ${RLP_DIR} && git clean -dfX
    CONFIGURE_COMMAND bash -c ${RLP_DIR}/autogen.sh && bash -c ${RLP_DIR}/configure --srcdir=${RLP_DIR} --disable-shared --enable-static=yes
    BUILD_COMMAND     make
    INSTALL_COMMAND   make install prefix=${RLP_BIN}
    BUILD_BYPRODUCTS  ${RLP_STATIC_LIB} ${RLP_BIN}/lib/libunivalue.a
)
add_library          (rlpvalue STATIC IMPORTED GLOBAL)
add_dependencies     (rlpvalue librlpvalue)
set_target_properties(rlpvalue PROPERTIES IMPORTED_LOCATION ${RLP_STATIC_LIB})
set_target_properties(rlpvalue PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${RLP_INCLUDES})

#
# nlohmann_json
#
if(NOT TARGET nlohmann_json)
    set(JSON_BuildTests OFF CACHE INTERNAL "")
    set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
    add_subdirectory(json EXCLUDE_FROM_ALL)
endif()

#
# GMP
#
find_library(gmp gmp)
if(NOT gmp)
  message(FATAL_ERROR "gmp not found")
endif()
