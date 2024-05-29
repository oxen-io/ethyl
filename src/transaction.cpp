#include "ethyl/transaction.hpp"

#include <oxenc/rlp_serialize.h>

namespace ethyl
{
Transaction::Transaction(std::string to, uint64_t value, uint64_t gasLimit,
                         std::string data)
    : to{std::move(to)}, value{std::move(value)}, gasLimit{gasLimit},
      data{std::move(data)} {}

/**
* Returns the raw Bytes of the EIP-1559 transaction, in order.
*
* Format: `[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
* accessList, signatureYParity, signatureR, signatureS]`
*
* For an unsigned tx this method uses the empty Bytes values for the
* signature parameters `v`, `r` and `s` for encoding.
*/
std::vector<unsigned char> Transaction::serialize() const {
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

    std::string serializedBytes = rlp_serialize(arr);
    std::vector<unsigned char> result;
    result.reserve(1 /*header*/ + serializedBytes.size());
    result.push_back(0x02);
    result.insert(result.end(), serializedBytes.begin(), serializedBytes.end());
    return result;
}

std::string Transaction::serializeAsHex() const {
    std::vector<unsigned char> serializedBytes = serialize();
    std::string result = oxenc::to_hex(serializedBytes.begin(), serializedBytes.end());
    return result;
}

Bytes32 Transaction::hash() const {
    std::vector<unsigned char> serializedBytes = serialize();
    Bytes32 result = utils::hashBytes(serializedBytes);
    return result;
}

std::string Transaction::hashAsHex() const {
    Bytes32 txHash = hash();
    std::string result = oxenc::to_hex(txHash.begin(), txHash.end());
    return result;
}

bool Signature::isEmpty() const {
  static constexpr Bytes32 zero = {};
  bool result =
      signatureYParity == 0 && signatureR == zero && signatureS == zero;
  return result;
}

void Signature::set(const ECDSACompactSignature& signature) {
    assert(signature.max_size() == 65);
    std::memcpy(signatureR.data(), &signature[0],  32);
    std::memcpy(signatureS.data(), &signature[32], 32);
    signatureYParity = static_cast<unsigned char>(signature[signature.max_size() - 1]);
}
}  // namespace ethyl
