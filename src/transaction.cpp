#include "ethyl/transaction.hpp"
#include "ethyl/utils.hpp"

#include <oxenc/rlp_serialize.h>

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
    using namespace oxenc;

    std::vector<std::variant<uint64_t, std::span<const unsigned char>, std::vector<unsigned char>, std::vector<uint64_t>>> arr;
    arr.push_back(chainId);
    arr.push_back(nonce);
    arr.push_back(maxPriorityFeePerGas);
    arr.push_back(maxFeePerGas);
    arr.push_back(gasLimit);
    arr.push_back(utils::fromHexString(to));
    arr.push_back(value);
    arr.push_back(utils::fromHexString(data));

    // Access list not going to use
    arr.push_back(std::vector<uint64_t>{});

    if (!sig.isEmpty()) {
        arr.push_back(sig.signatureYParity);
        arr.push_back(oxenc::rlp_big_integer(sig.signatureR));
        arr.push_back(oxenc::rlp_big_integer(sig.signatureS));
    }
    return "0x02" + oxenc::to_hex(rlp_serialize(arr));
}

std::string Transaction::hash() const {
    std::array<unsigned char, 32> hash = utils::hash_(serialized());
    std::string result = "0x" + oxenc::to_hex(hash.begin(), hash.end());
    return result;
}

bool Signature::isEmpty() const {
    return signatureYParity == 0 && signatureR.empty() && signatureS.empty();
}

void Signature::fromHex(std::string_view hex_str) {

    auto bytes = utils::fromHexString(hex_str);
    if (bytes.size() != 65) {
        throw std::invalid_argument("Input string length should be 130 characters for 65 bytes");
    }

    signatureR.resize(32);
    signatureS.resize(32);
    std::memcpy(signatureR.data(), bytes.data(), 32);
    std::memcpy(signatureS.data(), bytes.data() + 32, 32);
    signatureYParity = bytes[64];
}
