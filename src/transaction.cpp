#include "ethyl/transaction.hpp"
#include "ethyl/utils.hpp"

#include <rlpvalue.h>
#include <iostream>
#include <exception>

/**
 * Serialize the transaction into a hexadecimal string using RLP encoding.
 * This function handles both signed and unsigned transactions.
 *
 * Throws: std::runtime_error on failure to process any transaction component. 
 * Returns the raw Bytes of the EIP-1559 transaction, in order.
 *
 * Format: `[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
 * accessList, signatureYParity, signatureR, signatureS]`
 *
 * For an unsigned tx this method uses the empty Bytes values for the
 * signature parameters `v`, `r` and `s` for encoding.
 */
std::string Transaction::serialized() const {
    try {
        RLPValue arr(RLPValue::VARR);
        arr.setArray();

        // Helper lambda for repetitive operations to convert and append data
        auto appendSerializedData = [&](const auto& data, auto conversionFunction) {
            RLPValue temp_val;
            try {
                temp_val.assign(conversionFunction(data));
                arr.push_back(temp_val);
            } catch (const std::exception& e) {
                throw std::runtime_error("Error converting transaction data: " + std::string(e.what()));
            }
        };

        appendSerializedData(chainId, utils::intToBytes);
        appendSerializedData(nonce, utils::intToBytes);
        appendSerializedData(maxPriorityFeePerGas, utils::intToBytes);
        appendSerializedData(maxFeePerGas, utils::intToBytes);
        appendSerializedData(gasLimit, utils::intToBytes);
        appendSerializedData(to, utils::fromHexString);
        appendSerializedData(value, utils::intToBytes);
        appendSerializedData(data, utils::fromHexString);

        // Handle the access list, currently empty
        RLPValue access_list(RLPValue::VARR);
        access_list.setArray();
        arr.push_back(access_list);

        if (!sig.isEmpty()) {
            appendSerializedData(sig.signatureYParity, utils::intToBytes);
            appendSerializedData(sig.signatureR, utils::removeLeadingZeros);
            appendSerializedData(sig.signatureS, utils::removeLeadingZeros);
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
};

/**
 * Parses a signature from a hexadecimal string.
 * The string should be exactly 130 characters long after removing the "0x" prefix.
 *
 * Parameters:
 *   - hex_str: Hexadecimal string containing the signature.
 *
 * Throws: std::invalid_argument if the input format is incorrect.
 * Throws: std::runtime_error on parsing errors.
 */
void Signature::fromHex(std::string hex_str) {
    if (hex_str.size() >= 2 && hex_str.substr(0, 2) == "0x") {
        hex_str = hex_str.substr(2);
    }

    if (hex_str.size() != 130) {
        throw std::invalid_argument("Input string length should be 130 characters for 65 bytes (found " + std::to_string(hex_str.size()) + ")");
    }

    try {
        std::string r_str = hex_str.substr(0, 64);
        std::string s_str = hex_str.substr(64, 64);
        std::string y_parity_str = hex_str.substr(128, 2);

        signatureR = utils::fromHexString(r_str);
        signatureS = utils::fromHexString(s_str);
        signatureYParity = std::stoull(y_parity_str, nullptr, 16);
    } catch (const std::exception& e) {
        throw std::runtime_error("Error parsing hex string for signature: " + std::string(e.what()));
    }
}
