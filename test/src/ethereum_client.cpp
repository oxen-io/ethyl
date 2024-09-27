#include <iostream>

#include <oxenc/hex.h>

#include "ethyl/provider.hpp"
#include "ethyl/signer.hpp"
#include "ethyl/utils.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_all.hpp>
#include <catch2/catch_session.hpp>

using namespace oxenc::literals;
using namespace ethyl;

// Construct the client with the local RPC URL
inline constexpr auto PRIVATE_KEY               = "96a656cbd64281ea82257ca9978093b25117592287e4e07f5be660d1701f03e9"_hex_u;
inline constexpr std::string_view ADDRESS       = "0x2ccb8b65024e4aa9615a8e704dfb11be76674f1f";
inline constexpr std::string_view ANVIL_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
inline constexpr auto ANVIL_PRIVATE_KEY         = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"_hex_u;
Signer signer;

std::string ethRPC() {
    static auto* eth_rpc = std::getenv("ETH_RPC");
    if (eth_rpc && strlen(eth_rpc))
        return eth_rpc;
    return "127.0.0.1:8545"s;
}

int main(int argc, char *argv[]) {
    auto rpc = ethRPC();
    signer.provider->addClient("Client", rpc);
    std::cout << "Note to run these tests, ensure that a local Ethereum development network is running at " << rpc << "\n";
    int result = Catch::Session().run(argc, argv);
    return result;
}

TEST_CASE( "Get balance from sepolia network", "[ethereum]" ) {
    // Get the balance of the test address
    auto balance = signer.provider->getBalance(std::string(ANVIL_ADDRESS));

    // Check that the balance is greater than zero
    REQUIRE( balance != "" );
}

TEST_CASE( "HashTest", "[utils]" ) {
    std::string_view text = "hello world!";
    Bytes32 hash = utils::hashBytes(std::span(text.data(), text.size()));
    std::string hash_hello_world = oxenc::to_hex(hash.begin(), hash.end());
    REQUIRE( hash_hello_world == "57caa176af1ac0433c5df30e8dabcd2ec1af1e92a26eced5f719b88458777cd6" );
}

TEST_CASE( "SigningTest", "[signer]" ) {
    Bytes32 hash = utils::hashBytes("Hello World!\n");
    std::string hash_hello_world = oxenc::to_hex(hash.begin(), hash.end());
    const auto signature_bytes = signer.signMessage("Hello World!", PRIVATE_KEY);
    std::string signature_hex = oxenc::to_hex(signature_bytes.begin(), signature_bytes.end());
    REQUIRE( signature_hex == "35f409302082e02b5126c82be93a3946d30e93722ce3ff87bdb01fc385fe312054f3fade7fab80dcabadabf96af75577327dfd064abd47a36543a475e04840e701" );
}

TEST_CASE( "Get address from private key", "[signer]" ) {
    std::string created_address = signer.secretKeyToAddressString(PRIVATE_KEY);
    REQUIRE( created_address == ADDRESS );
}

//Raw transaction data
//{
  //type: null,
  //to: '0xA6C077fd9283421C657EcEa8a9c1422cc6CEbc80',
  //data: '0x',
  //nonce: 1,
  //gasLimit: '21000',
  //gasPrice: null,
  //maxPriorityFeePerGas: null,
  //maxFeePerGas: null,
  //value: '1000000000000000000',
  //chainId: '1',
  //sig: null,
  //accessList: null
//}
//0x02e70101808082520894a6c077fd9283421c657ecea8a9c1422cc6cebc80880de0b6b3a764000080c0
TEST_CASE( "Serialise a raw transaction correctly", "[transaction]" ) {
    Transaction tx("0xA6C077fd9283421C657EcEa8a9c1422cc6CEbc80", 1000000000000000000, 21000);
    tx.nonce = 1;
    tx.chainId = 1;
    std::string raw_tx = tx.serializeAsHex();
    std::string correct_raw_tx = "02e70101808082520894a6c077fd9283421c657ecea8a9c1422cc6cebc80880de0b6b3a764000080c0";
    REQUIRE(raw_tx == correct_raw_tx);
}

TEST_CASE( "Hashes an unsigned transaction correctly", "[transaction]" ) {
    Transaction tx("0xA6C077fd9283421C657EcEa8a9c1422cc6CEbc80", 1000000000000000000, 21000);
    tx.nonce = 1;
    tx.chainId = 1;
    std::string unsigned_hash = tx.hashAsHex();
    std::string correct_hash = "f81a17092cfb066efa3ff6ef92016adc06ff66a64327359c4003d215d56128b3";
    REQUIRE(unsigned_hash == correct_hash);
}

TEST_CASE( "Signs an unsigned transaction correctly", "[transaction]" ) {
    Transaction tx("0xA6C077fd9283421C657EcEa8a9c1422cc6CEbc80", 1000000000000000000, 21000);
    tx.nonce = 1;
    tx.chainId = 1;
    const auto signature_hex_string = signer.signTransactionAsHex(tx, PRIVATE_KEY);
    REQUIRE(signature_hex_string == "02f86a0101808082520894a6c077fd9283421c657ecea8a9c1422cc6cebc80880de0b6b3a764000080c080a084987299f8dd115333356ab03430ca8de593e03ba03d4ecd72daf15205119cf8a0216c9869da3497ae96dcb98713908af1a0abf866c12d51def821caf0374cccbb" );
}

TEST_CASE( "Does a self transfer", "[transaction]" ) {
    auto provider = signer.provider;
    Transaction tx(std::string(ANVIL_ADDRESS), 100000000000000, 21000);
    tx.chainId = 31337; //LOCAL
    tx.nonce = provider->getTransactionCount(std::string(ANVIL_ADDRESS), "pending");
    const auto feeData = provider->getFeeData();
    tx.maxFeePerGas = feeData.maxFeePerGas;
    tx.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;
    const auto signature_hex_string = signer.signTransaction(tx, ANVIL_PRIVATE_KEY);
    const auto hash = provider->sendTransaction(tx);
    REQUIRE(hash != "");
    REQUIRE(provider->transactionSuccessful(hash));
}

TEST_CASE( "Does a self transfer on network using signer to populate", "[transaction]" ) {
    Transaction tx(std::string(ANVIL_ADDRESS), 100000000000000, 21000);
    const auto hash = signer.sendTransaction(tx, ANVIL_PRIVATE_KEY);
    REQUIRE(hash != "");
    REQUIRE(signer.provider->transactionSuccessful(hash));
}

TEST_CASE("Test multiple clients", "[provider]") {
    auto provider = Provider::make_provider();
    provider->setTimeout(std::chrono::milliseconds(1000));
    provider->addClient("Client", ethRPC());
    provider->addClient("Bad Client", "127.3.4.5:12345"); // Add non-existent client
    CHECK(provider->connectToNetwork());
}
