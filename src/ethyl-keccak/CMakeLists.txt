# The keccak implementation here is copied from oxen-core; we only compile this if building ethyl
# standalone; when building inside oxen-core we set the ENABLE_CRYPTO_LIBRARY to false so that the
# ethyl-keccak just transitively links to cncrypto instead.


if(${PROJECT_NAME}_ENABLE_CRYPTO_LIBRARY)
    add_library(ethyl-keccak STATIC crypto/keccak.cpp)
    target_include_directories(ethyl-keccak PUBLIC .)
    target_link_libraries(ethyl-keccak PRIVATE oxenc::oxenc)
else()
    add_library(ethyl-keccak INTERFACE)
    target_link_libraries(ethyl-keccak INTERFACE cncrypto)
endif()
