
include(../cmake/system_or_submodule.cmake)
find_package(PkgConfig REQUIRED)


# Force shared libs off for any libraries we build inside here so that if we build a shared lib we
# don't end up with a libspdlog.so or whatever that would need to be distributed alongside the
# libquic.so
set(BUILD_SHARED_LIBS OFF)


#
# CPR
#
if(NOT TARGET cpr::cpr)
    find_package(CURL REQUIRED COMPONENTS HTTP HTTPS SSL)
    file(GLOB cpr_sources ${conf_depends} cpr/cpr/*.cpp)
    file(READ cpr/CMakeLists.txt cpr_cmakelists_txt)
    if(NOT cpr_cmakelists_txt MATCHES "project\\(cpr VERSION ([0-9]+)\\.([0-9]+)\\.([0-9]+) LANGUAGES CXX\\)")
        message(FATAL_ERROR "Failed to detect cpr version")
    endif()
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/cpr)
    set(cpr_VERSION_MAJOR "${CMAKE_MATCH_1}")
    set(cpr_VERSION_MINOR "${CMAKE_MATCH_2}")
    set(cpr_VERSION_PATCH "${CMAKE_MATCH_3}")
    set(cpr_VERSION "${cpr_VERSION_MAJOR}.${cpr_VERSION_MINOR}.${cpr_VERSION_PATCH}")
    set(cpr_VERSION_NUM "(${cpr_VERSION_MAJOR} * 0x10000 + ${cpr_VERSION_MINOR} * 0x100 + ${cpr_VERSION_PATCH})")
    configure_file("cpr/cmake/cprver.h.in" "${CMAKE_CURRENT_BINARY_DIR}/include/cpr/cprver.h")

    add_library(cpr STATIC EXCLUDE_FROM_ALL ${cpr_sources})
    target_link_libraries(cpr PUBLIC CURL::libcurl)
    target_include_directories(cpr PUBLIC cpr/include "${CMAKE_CURRENT_BINARY_DIR}/include")
    target_compile_definitions(cpr PUBLIC CPR_CURL_NOSIGNAL)
    add_library(cpr::cpr ALIAS cpr)
endif()

#
# SECP256k1
#
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
set(SECP256K1_VALGRIND OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
system_or_submodule(SECP256K1 secp256k1 libsecp256k1>=0.2 secp256k1)

#
# Catch2
#
if(NOT TARGET Catch2)
    add_subdirectory(Catch2 EXCLUDE_FROM_ALL)
endif()

#
# oxen-encoding
#
if(NOT TARGET oxenc::oxenc)
    system_or_submodule(OXENC oxenc liboxenc>=1.1.0 oxen-encoding)
endif()

if(NOT TARGET oxen::logging)
    add_subdirectory(oxen-logging EXCLUDE_FROM_ALL)
endif()
oxen_logging_add_source_dir("${PROJECT_SOURCE_DIR}")

#
# nlohmann_json
#
if(NOT TARGET nlohmann_json::nlohmann_json)
    set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
    system_or_submodule(NLOHMANN nlohmann_json nlohmann_json>=3.7.0 json)
endif()

#
# GMP
#

pkg_check_modules(GMP gmp IMPORTED_TARGET REQUIRED)
add_library(gmp INTERFACE)
target_link_libraries(gmp INTERFACE PkgConfig::GMP)
message(STATUS "Found gmp ${GMP_VERSION}")
