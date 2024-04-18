#include "ethyl/transaction.hpp"
#include "ethyl/utils.hpp"

#include <rlpvalue.h>
#include <iostream>
#include <exception>

// Optimized helper function to append data to the RLP array
// Declared inline to hint to the compiler that it should avoid function call overhead by integrating the function's body at each call site.
inline void appendDataToRLP(RLPValue& arr, const auto& value, auto convertFunction) {
    RLPValue temp_val;
    temp_val.assign(convertFunction(value));
    arr.push_back(temp_val);
}

std::string Transaction::serialized() const {
    try {
        RLPValue arr(RLPValue::VARR);
        arr.setArray();
        arr.reserve(11);  // Pre-allocate memory for known number of elements without signature

        // Serialize transaction data using the optimized helper function
        appendDataToRLP(arr, chainId, utils::intToBytes);
        appendDataToRLP(arr, nonce, utils::intToBytes);
        appendDataToRLP(arr, maxPriorityFeePerGas, utils::intToBytes);
        appendDataToRLP(arr, maxFeePerGas, utils::intToBytes);
        appendDataToRLP(arr, gasLimit, utils::intToBytes);
        appendDataToRLP(arr, to, utils::fromHexString);
        appendDataToRLP(arr, value, utils::intToBytes);
        appendDataToRLP(arr, this->data, utils::fromHexString);  // Explicitly use member variable

        // Handle the access list, which is empty in this implementation
        RLPValue access_list(RLPValue::VARR);
        access_list.setArray();
        arr.push_back(access_list);

        if (!sig.isEmpty()) {
            arr.reserve(14);  // Adjust the reservation to include signature elements
            appendDataToRLP(arr, sig.signatureYParity, utils::intToBytes);
            appendDataToRLP(arr, sig.signatureR, utils::removeLeadingZeros);
            appendDataToRLP(arr, sig.signatureS, utils::removeLeadingZeros);
        }

        return "0x02" + utils::toHexString(arr.write());
    } catch (const std::exception& e) {
        std::cerr << "Error serializing transaction: " << e.what() << std::endl;
        throw;
    }
}

std::string Transaction::hash() const {
    return "0x" + utils::toHexString(utils::hash(serialized()));
}

bool Signature::isEmpty() const {
    return signatureYParity == 0 && signatureR.empty() && signatureS.empty();
}

void Signature::fromHex(std::string hex_str) {
    if (hex_str.size() >= 2 && hex_str[0] == '0' && hex_str[1] == 'x') {
        hex_str = hex_str.substr(2);
    }

    if (hex_str.size() != 130) {
        throw std::invalid_argument("Input string length should be 130 characters for 65 bytes");
    }

    signatureR = utils::fromHexString(hex_str.substr(0, 64));
    signatureS = utils::fromHexString(hex_str.substr(64, 64));
    signatureYParity = std::stoull(hex_str.substr(128, 2), nullptr, 16);
}
