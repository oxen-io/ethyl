set(sources
    src/utils.cpp
    src/provider.cpp
    src/transaction.cpp
)

if(${PROJECT_NAME}_ENABLE_SIGNER)
    list(APPEND sources src/signer.cpp)
endif()


set(test_sources
  src/basic.cpp
  src/ethereum_client.cpp
)
