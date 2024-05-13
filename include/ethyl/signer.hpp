#pragma once

#include <array>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "provider.hpp"

typedef struct secp256k1_context_struct secp256k1_context; // forward decl

namespace ethyl
{
class Signer {
private:
    secp256k1_context* ctx;
    std::shared_ptr<Provider> provider;

    uint64_t maxPriorityFeePerGas = 0;
    uint64_t maxFeePerGas = 0;
    uint64_t gasPrice = 0;

public:
    Signer();
    Signer(const std::shared_ptr<Provider>& client);
    ~Signer();

    // Returns <Pubkey, Seckey>
    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_key_pair();
    std::array<unsigned char, 20>                                     secretKeyToAddress(std::span<const unsigned char> seckey);
    std::string                                                       secretKeyToAddressString(std::span<const unsigned char> seckey);

    std::vector<unsigned char> sign(const std::array<unsigned char, 32>& hash, std::span<const unsigned char> seckey);
    std::vector<unsigned char> sign(std::string_view hash, std::span<const unsigned char> seckey);

    // Client usage methods
    bool hasProvider() const { return static_cast<bool>(provider); }
    std::shared_ptr<Provider> getProvider() { return provider; }


    std::vector<unsigned char> signMessage(std::string_view message, std::span<const unsigned char> seckey);
    std::string signTransaction(Transaction& tx, std::span<const unsigned char> seckey);

    void populateTransaction(Transaction& tx, std::string sender_address);
    std::string sendTransaction(Transaction& tx, std::span<const unsigned char> seckey);


private:
    void initContext();
};
}; // namespace ethyl
