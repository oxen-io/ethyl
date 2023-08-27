#pragma once

#include <string>
#include <vector>

#include "ethyl/utils.hpp"

struct Signature {
    uint64_t signatureYParity = 0;
    std::vector<unsigned char> signatureR = {};
    std::vector<unsigned char> signatureS = {};

    bool isEmpty() const;

    void fromHex(std::string hex_str);
};

class Transaction {
public:
    uint64_t chainId;
    uint64_t nonce;                     
    uint64_t maxPriorityFeePerGas;
    uint64_t maxFeePerGas;
    std::string to;
    uint64_t value;     
    uint64_t gasLimit;
    std::string data;
    Signature sig;

    // Constructor                                                                                                        
    // (toAddress, value, gasLimit, data)
    Transaction(const std::string& _to , uint64_t _value , uint64_t _gasLimit = 21000, const std::string& _data = "") 
        : chainId(0), nonce(0), maxPriorityFeePerGas(0), maxFeePerGas(0), to(_to), value(_value), gasLimit(_gasLimit), data(_data) {}

    std::string serialized() const;
    std::string hash() const;

};
