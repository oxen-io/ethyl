#include "ethyl/signer.hpp"

#include "ethyl/ecdsa_util.h"
#include "ethyl/utils.hpp"
#include "ethyl/transaction.hpp"

#include <secp256k1_recovery.h>

#include <array>
#include <cstring>

namespace ethyl
{
Signer::Signer() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char randomize[32];
    if (!ethyl_fill_random(randomize, sizeof(randomize))) {
        throw std::runtime_error("Failed to generate randomness");
    }
    if (!secp256k1_context_randomize(ctx, randomize))
        throw std::runtime_error("Failed to randomize context");
}

Signer::~Signer() {
    secp256k1_context_destroy(ctx);
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> Signer::generate_key_pair() {
    unsigned char seckey[32];
    unsigned char compressed_pubkey[33];
    size_t len;
    secp256k1_pubkey pubkey;

    while (1) {
        if (!ethyl_fill_random(seckey, sizeof(seckey))) {
            throw std::runtime_error("Failed to generate randomness");
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey))
        throw std::runtime_error("Failed to create pubkey");

    len = sizeof(compressed_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED))
        throw std::runtime_error("Failed to serialize pubkey");
    assert(len == sizeof(compressed_pubkey));

    return {std::vector<unsigned char>(seckey, seckey + sizeof(seckey)), 
            std::vector<unsigned char>(compressed_pubkey, compressed_pubkey + sizeof(compressed_pubkey))};
}

Bytes20 Signer::secretKeyToAddress(std::span<const unsigned char> seckey) {
    std::string address;

    // Verify the private key.
    if (!secp256k1_ec_seckey_verify(ctx, seckey.data())) {
        throw std::runtime_error("Failed to verify secret key");
    }

    // Compute the public key.
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.data())) {
        throw std::runtime_error("Failed to create public key");
    }

    // Serialize the public key in uncompressed form.
    std::array<unsigned char, 1 /*header byte 0x04*/ + sizeof(secp256k1_pubkey)> pub;
    size_t pub_len = pub.max_size();
    secp256k1_ec_pubkey_serialize(ctx, pub.data(), &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    // Skip the type byte by trimming the header byte (0x04)
    std::string_view pub_string =
            std::string_view(reinterpret_cast<const char*>(pub.data()) + 1, pub.size() - 1);
    Bytes32 hashed_pub = utils::hashBytes(pub_string);

    // The last 20 bytes of the Keccak-256 hash of the public key in hex is the address.
    Bytes20 result = {};
    std::memcpy(result.data(), hashed_pub.data() + hashed_pub.size() - result.size(), result.size());
    return result;
}

std::string Signer::secretKeyToAddressString(std::span<const unsigned char> seckey)
{
    Bytes20 address = secretKeyToAddress(seckey);
    std::string result = "0x" + oxenc::to_hex(address.begin(), address.end());
    return result;
}

void Signer::populateTransaction(Transaction& tx, std::string senderAddress) {
    // Check if the signer has a client
    if (provider.clients.empty())
        throw std::runtime_error("Signer does not have a provider with any RPC backends set. Ensure that the provider has atleast one client");

    // If nonce is not set, get it from the network
    if (tx.nonce == 0) {
        tx.nonce = provider.getTransactionCount(senderAddress, "pending");
    }

    // Get network's chain ID
    uint32_t networkChainId = provider.getNetworkChainId();

    // Check and set chainId
    if (tx.chainId != 0) {
        if (tx.chainId != networkChainId) {
            throw std::runtime_error("Chain ID on transaction does not match providers Chain ID");
        }
    } else {
        tx.chainId = networkChainId;
    }

    // Get fee data
    const auto feeData = provider.getFeeData();
    tx.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;

    if (tx.maxFeePerGas == 0) {
        tx.maxFeePerGas = feeData.maxFeePerGas;
    }

    if (tx.maxPriorityFeePerGas == 0) {
        tx.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;
    }
}

std::vector<unsigned char> sign_old(secp256k1_context *ctx, const std::array<unsigned char, 32>& hash, std::span<const unsigned char> seckey) {
    secp256k1_ecdsa_recoverable_signature sig;
    unsigned char serialized_signature[64];
    int recid;

    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash.data(), seckey.data(), NULL, NULL))
        throw std::runtime_error("Failed to sign");

    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, serialized_signature, &recid, &sig))
        throw std::runtime_error("Failed to serialize signature");

    // Create a vector and fill it with the serialized signature
    std::vector<unsigned char> signature(serialized_signature, serialized_signature + sizeof(serialized_signature));

    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    // TODO sean it looks like the EIP modifys how this is done in new ones from that EIP
    //
    // If block.number >= FORK_BLKNUM and v = CHAIN_ID * 2 + 35 or v = CHAIN_ID * 2 + 36,
    // then when computing the hash of a transaction for purposes of recovering,
    // instead of hashing six rlp encoded elements (nonce, gasprice, startgas, to, value, data),
    // hash nine rlp encoded elements (nonce, gasprice, startgas, to, value, data, chainid, 0, 0).
    // The currently existing signature scheme using v = 27 and v = 28 remains valid and continues to operate under the same rules as it did previously.
    signature.push_back(static_cast<unsigned char>(recid));
    return signature;
}

ECDSACompactSignature Signer::sign32(std::span<const unsigned char, 32> hash, std::span<const unsigned char> seckey) {
    secp256k1_ecdsa_recoverable_signature sig = {};
    ECDSACompactSignature result = {};
    int recoveryID = 0;

    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash.data(), seckey.data(),
                                          NULL, NULL))
      throw std::runtime_error("Failed to sign");

    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, result.data(), &recoveryID, &sig))
      throw std::runtime_error("Failed to serialize signature");

    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    // TODO sean it looks like the EIP modifys how this is done in new ones from that EIP
    //
    // If block.number >= FORK_BLKNUM and v = CHAIN_ID * 2 + 35 or v = CHAIN_ID * 2 + 36,
    // then when computing the hash of a transaction for purposes of recovering,
    // instead of hashing six rlp encoded elements (nonce, gasprice, startgas, to, value, data),
    // hash nine rlp encoded elements (nonce, gasprice, startgas, to, value, data, chainid, 0, 0).
    // The currently existing signature scheme using v = 27 and v = 28 remains valid and continues to operate under the same rules as it did previously.
    assert(recoveryID <= 255);
    result.back() = static_cast<unsigned char>(recoveryID);
    return result;
}

ECDSACompactSignature Signer::signMessage(std::string_view message, std::span<const unsigned char> seckey) {
    Bytes32 hash = utils::hashBytes(message);
    ECDSACompactSignature result = sign32(hash, seckey);
    return result;
}

std::vector<unsigned char> Signer::signTransaction(Transaction& tx, std::span<const unsigned char> seckey) {
    ECDSACompactSignature signature = sign32(tx.hash(), seckey);
    tx.sig.set(signature);
    std::vector<unsigned char> result = tx.serialize();
    return result;
}

std::string Signer::signTransactionAsHex(Transaction& tx, std::span<const unsigned char> seckey) {
    std::vector<unsigned char> signature = signTransaction(tx, seckey);
    std::string result = oxenc::to_hex(signature.begin(), signature.end());
    return result;
}

std::string Signer::sendTransaction(Transaction& tx, std::span<const unsigned char> seckey) {
    const auto senders_address = secretKeyToAddressString(seckey);
    populateTransaction(tx, senders_address);
    signTransaction(tx, seckey);
    const auto result = provider.sendTransaction(tx);
    return result;
}
}; // namespace ethyl
