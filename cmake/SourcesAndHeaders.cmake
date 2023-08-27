set(sources
    src/utils.cpp
    src/provider.cpp
    src/signer.cpp
    src/transaction.cpp
)

set(headers
    include/ethyl/utils.hpp
    include/ethyl/provider.hpp
    include/ethyl/signer.hpp
    include/ethyl/transaction.hpp
)

set(test_sources
  src/basic.cpp
  src/ethereum_client.cpp
)
