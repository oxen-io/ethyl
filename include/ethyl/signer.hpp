#pragma once

#include "provider.hpp"
#include "utils.hpp"

#include <span>
#include <string>
#include <string_view>
#include <vector>

typedef struct secp256k1_context_struct secp256k1_context; // forward decl

namespace ethyl
{
class Signer {
public:
    Signer();
    ~Signer();

    // Returns <Pubkey, Seckey>
    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_key_pair();
    Bytes20     secretKeyToAddress(std::span<const unsigned char> seckey);
    std::string secretKeyToAddressString(std::span<const unsigned char> seckey);

    /// Sign a 32 byte hash with secp256k1 and return an ECDSA signature in
    /// compact form of 65 bytes (64 bytes + recovery ID)
    ECDSACompactSignature sign32(std::span<const unsigned char, 32> bytes, std::span<const unsigned char> seckey);

    /// Sign the message by hashing `message` with keccak into 32 bytes and then
    /// sign the 32 bytes using `seckey` with secp256k1.
    ECDSACompactSignature signMessage(std::string_view message, std::span<const unsigned char> seckey);

    /// Sign a transaction with the given `seckey`. The transaction is updated
    /// to store the signature as computed by this function. This function
    /// returns the the RLP serialised TX.
    std::vector<unsigned char> signTransaction(Transaction& tx, std::span<const unsigned char> seckey);

    /// See `signTransaction`. This function returns the RLP serialised TX in
    /// hex without a '0x' prefix.
    std::string signTransactionAsHex(Transaction& tx, std::span<const unsigned char> seckey);

    void populateTransaction(Transaction& tx, std::string sender_address);

    std::string sendTransaction(Transaction& tx, std::span<const unsigned char> seckey);

    std::shared_ptr<Provider> provider = Provider::make_provider();

private:
    secp256k1_context* ctx;
    uint64_t maxPriorityFeePerGas = 0;
    uint64_t maxFeePerGas = 0;
    uint64_t gasPrice = 0;

};
}; // namespace ethyl
