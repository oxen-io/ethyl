#pragma once

#include "utils.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace ethyl
{
struct Signature
{
    bool init = false;
    uint64_t signatureYParity = 0;
    Bytes32 signatureR;
    Bytes32 signatureS;
    void set(ECDSACompactSignature const &signature);
};

struct Transaction
{
    Transaction() = default;

    Transaction(std::string to, uint64_t value, uint64_t gasLimit = 21000,
                std::string data = "");

    /// Serialise the transaction into a RLP serialised payload.
    std::vector<unsigned char> serialize() const;

    /// See `serialize`. The RLP payload is returned in hex without a '0x'
    /// prefix.
    std::string serializeAsHex() const;

    /// Calculate the transaction hash by RLP serializing the contents and
    /// applying a keccak hash.
    Bytes32 hash() const;

    /// Calculate the transaction hash by calling `hash` and returning the hex
    /// representation of the 32 byte hash without a '0x' prefix.
    std::string hashAsHex() const;

    uint64_t chainId = 0;
    uint64_t nonce = 0;
    uint64_t maxPriorityFeePerGas = 0;
    uint64_t maxFeePerGas = 0;
    std::string to;
    uint64_t value = 0;
    uint64_t gasLimit = 0;
    std::string data;
    Signature sig;
};
}  // namespace ethyl
