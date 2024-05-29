#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ethyl
{
struct Signature {
    uint64_t signatureYParity = 0;
    std::vector<unsigned char> signatureR = {};
    std::vector<unsigned char> signatureS = {};

    bool isEmpty() const;

    void fromHex(std::string_view hex_str);
};

class Transaction {
public:
    uint64_t chainId = 0;
    uint64_t nonce = 0;
    uint64_t maxPriorityFeePerGas = 0;
    uint64_t maxFeePerGas = 0;
    std::string to;
    uint64_t value;     
    uint64_t gasLimit;
    std::string data;
    Signature sig;

    // Constructor                                                                                                        
    // (toAddress, value, gasLimit, data)
    Transaction(std::string to, uint64_t value, uint64_t gasLimit = 21000, std::string data = "")
        : to{std::move(to)}, value{std::move(value)}, gasLimit{gasLimit}, data{std::move(data)} {}

    std::string serialized() const;
    std::string hash() const;

};
}  // namespace ethyl
