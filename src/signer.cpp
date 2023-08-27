#include "ethyl/signer.hpp"

#include <stdio.h>
#include <array>
#include <stdexcept>
#include <iostream>

#include "ethyl/ecdsa_util.h"
#include "ethyl/utils.hpp"
#include "ethyl/transaction.hpp"

#include <secp256k1_recovery.h>

Signer::Signer() {
    initContext();
}

Signer::Signer(const std::shared_ptr<Provider>& _provider) : provider(_provider) {
    initContext();
}

void Signer::initContext() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char randomize[32];
    if (!fill_random(randomize, sizeof(randomize))) {
        throw std::runtime_error("Failed to generate randomness");
    }
    int return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);
}

Signer::~Signer() {
    secp256k1_context_destroy(ctx);
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> Signer::generate_key_pair() {
    unsigned char seckey[32];
    unsigned char compressed_pubkey[33];
    size_t len;
    int return_val;
    secp256k1_pubkey pubkey;

    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            throw std::runtime_error("Failed to generate randomness");
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    assert(return_val);

    len = sizeof(compressed_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    assert(len == sizeof(compressed_pubkey));

    return {std::vector<unsigned char>(seckey, seckey + sizeof(seckey)), 
            std::vector<unsigned char>(compressed_pubkey, compressed_pubkey + sizeof(compressed_pubkey))};
}

std::string Signer::addressFromPrivateKey(const std::vector<unsigned char>& seckey) {
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
    std::vector<unsigned char> pub(65);
    size_t pub_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pub.data(), &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    // Skip the type byte.
    std::string pub_string(pub.begin() + 1, pub.end());
    auto hashed_pub = utils::hash(pub_string);

    // The last 20 bytes of the Keccak-256 hash of the public key in hex is the address.
    address = utils::toHexString(hashed_pub);
    address = address.substr(address.size() - 40);

    return "0x" + address;
}


std::vector<unsigned char> Signer::sign(const std::array<unsigned char, 32>& hash, const std::vector<unsigned char>& seckey) {
    secp256k1_ecdsa_recoverable_signature sig;
    unsigned char serialized_signature[64];
    int recid;
    int return_val;

    return_val = secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash.data(), seckey.data(), NULL, NULL);
    assert(return_val);

    return_val = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, serialized_signature, &recid, &sig);
    assert(return_val);

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

std::vector<unsigned char> Signer::sign(const std::string& hash, const std::vector<unsigned char>& seckey) {
    return sign(utils::fromHexString32Byte(hash), seckey);
}

void Signer::populateTransaction(Transaction& tx, std::string sender_address) {
    // Check if the signer has a client
    if (!hasProvider()) {
        throw std::runtime_error("Signer does not have a provider");
    }

    // If nonce is not set, get it from the network
    if (tx.nonce == 0) {
        tx.nonce = provider->getTransactionCount(sender_address, "pending");
    }

    // Get network's chain ID
    uint32_t networkChainId = provider->getNetworkChainId();

    // Check and set chainId
    if (tx.chainId != 0) {
        if (tx.chainId != networkChainId) {
            throw std::runtime_error("Chain ID on transaction does not match providers Chain ID");
        }
    } else {
        tx.chainId = networkChainId;
    }

    // Get fee data
    const auto feeData = provider->getFeeData();
    tx.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;

    if (tx.maxFeePerGas == 0) {
        tx.maxFeePerGas = feeData.maxFeePerGas;
    }

    if (tx.maxPriorityFeePerGas == 0) {
        tx.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;
    }
}

// Hash the message and sign
std::vector<unsigned char> Signer::signMessage(const std::string& message, const std::vector<unsigned char>& seckey) {
    return sign(utils::hash(message), seckey);
}

// Hash the transaction and sign
std::string Signer::signTransaction(Transaction& txn, const std::vector<unsigned char>& seckey) {
    const auto signature_hex = utils::toHexString(sign(txn.hash(), seckey));
    txn.sig.fromHex(signature_hex);

    return txn.serialized();
}

// Populates the txn, signs and sends
std::string Signer::sendTransaction(Transaction& txn, const std::vector<unsigned char>& seckey) {
    const auto senders_address = addressFromPrivateKey(seckey);

    populateTransaction(txn, senders_address);
    const auto signature_hex = utils::toHexString(sign(txn.hash(), seckey));
    txn.sig.fromHex(signature_hex);
    const auto hash = provider->sendTransaction(txn);
    return hash;
}
