#include "ethyl/transaction.hpp"
#include "ethyl/utils.hpp"

#include <rlpvalue.h>
#include <iostream>

/**
* Returns the raw Bytes of the EIP-1559 transaction, in order.
*
* Format: `[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
* accessList, signatureYParity, signatureR, signatureS]`
*
* For an unsigned tx this method uses the empty Bytes values for the
* signature parameters `v`, `r` and `s` for encoding.
*/
std::string Transaction::serialized() const {
    RLPValue arr(RLPValue::VARR);
    arr.setArray();
    RLPValue temp_val;
    temp_val.clear();
    temp_val.assign(utils::intToBytes(chainId));
    arr.push_back(temp_val);
    temp_val.assign(utils::intToBytes(nonce));
    arr.push_back(temp_val);
    temp_val.assign(utils::intToBytes(maxPriorityFeePerGas));
    arr.push_back(temp_val);
    temp_val.assign(utils::intToBytes(maxFeePerGas));
    arr.push_back(temp_val);
    temp_val.assign(utils::intToBytes(gasLimit));
    arr.push_back(temp_val);
    temp_val.assign(utils::fromHexString(to));
    arr.push_back(temp_val);
    temp_val.assign(utils::intToBytes(value));
    arr.push_back(temp_val);
    temp_val.assign(utils::fromHexString(data));
    arr.push_back(temp_val);

    // Access list not going to use
    RLPValue access_list(RLPValue::VARR);
    access_list.setArray();
    arr.push_back(access_list);

    if (!sig.isEmpty()) {
        temp_val.assign(utils::intToBytes(sig.signatureYParity));
        arr.push_back(temp_val);
        temp_val.assign(utils::removeLeadingZeros(sig.signatureR));
        arr.push_back(temp_val);
        temp_val.assign(utils::removeLeadingZeros(sig.signatureS));
        arr.push_back(temp_val);
    }
    return "0x02" + utils::toHexString(arr.write());
}

std::string Transaction::hash() const {
    return "0x" + utils::toHexString(utils::hash(serialized()));
}

bool Signature::isEmpty() const {
    return signatureYParity == 0 && signatureR.empty() && signatureS.empty();
};

void Signature::fromHex(std::string hex_str) {

    // Check for "0x" prefix and remove it
    if(hex_str.size() >= 2 && hex_str[0] == '0' && hex_str[1] == 'x') {
        hex_str = hex_str.substr(2);
    }

    if(hex_str.size() != 130) {
        throw std::invalid_argument("Input string length should be 130 characters for 65 bytes");
    }

    // Each byte is represented by 2 characters, so multiply indices by 2
    std::string r_str = hex_str.substr(0, 64);
    std::string s_str = hex_str.substr(64, 64);
    std::string y_parity_str = hex_str.substr(128, 2);

    signatureR = utils::fromHexString(r_str);
    signatureS = utils::fromHexString(s_str);
    signatureYParity = std::stoull(y_parity_str, nullptr, 16);
}
