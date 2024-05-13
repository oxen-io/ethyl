// provider.cpp
#include <chrono>
#include <iostream>
#include <thread>

#include <cpr/cpr.h>
#pragma GCC diagnostic push
#ifndef __clang__
#pragma GCC diagnostic ignored "-Wuseless-cast"
#endif
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

#include "ethyl/provider.hpp"
#include "ethyl/utils.hpp"

#include <gmpxx.h>

namespace ethyl
{
Provider::Provider(std::string name, std::string url)
    : clientName{std::move(name)}, url{std::move(url)} {
    // Initialize client
}

void Provider::connectToNetwork() {
    // Here we can verify connection by calling some simple JSON RPC method like `net_version`
    auto response = makeJsonRpcRequest("net_version", cpr::Body("{}"));
    if (response.status_code == 200) {
        std::cout << "Connected to the Ethereum network.\n";
    } else {
        std::cout << "Failed to connect to the Ethereum network.\n";
    }
}

void Provider::disconnectFromNetwork() {
    // Code to disconnect from Ethereum network
    std::cout << "Disconnected from the Ethereum network.\n";
}

cpr::Response Provider::makeJsonRpcRequest(std::string_view method, const nlohmann::json& params) {
    if (url.str() == "")
        throw std::runtime_error("No URL provided to provider");
    nlohmann::json bodyJson;
    bodyJson["jsonrpc"] = "2.0";
    bodyJson["method"] = method;
    bodyJson["params"] = params;
    bodyJson["id"] = 1;

    cpr::Body body(bodyJson.dump());

    std::lock_guard lock{mutex};
    session.SetUrl(url);
    session.SetBody(body);
    session.SetHeader({{"Content-Type", "application/json"}});
    return session.Post();
}

nlohmann::json Provider::callReadFunctionJSON(const ReadCallData& callData, std::string_view blockNumber) {
    nlohmann::json result = {};

    // Prepare the params for the eth_call request
    nlohmann::json params  = nlohmann::json::array();
    params[0]["to"]        = callData.contractAddress;
    params[0]["data"]      = callData.data;
    params[1]              = blockNumber; // use the provided block number or default to "latest"
    cpr::Response response = makeJsonRpcRequest("eth_call", params);

    if (response.status_code == 200) {
        nlohmann::json responseJson = nlohmann::json::parse(response.text);
        if (!responseJson["result"].is_null()) {
            result = responseJson["result"];
            return result;
        }
    }

    std::stringstream stream;
    stream << "'eth_call' invoked on node for block '" << blockNumber
           << "' to '" << callData.contractAddress
           << "' with data payload '" << callData.data
           << "' however it returned a response that does not have a result: "
           << response.text;
    throw std::runtime_error(stream.str());
}

std::string Provider::callReadFunction(const ReadCallData& callData, std::string_view blockNumber) {
    std::string result = callReadFunctionJSON(callData, blockNumber);
    return result;
}

std::string Provider::callReadFunction(const ReadCallData& callData, uint64_t blockNumberInt) {
    std::stringstream stream;
    stream << "0x" << std::hex << blockNumberInt; // Convert uint64_t to hex string
    std::string blockNumberHex = stream.str();
    std::string result         = callReadFunctionJSON(callData, blockNumberHex);
    return result;
}

uint32_t Provider::getNetworkChainId() {
    // Make the request takes no params
    nlohmann::json params = nlohmann::json::array();
    cpr::Response response = makeJsonRpcRequest("net_version", params);

    if (response.status_code == 200) {
        // Parse the response
        nlohmann::json responseJson = nlohmann::json::parse(response.text);

        // Check if the result field is present and not null, if it exists then it contains the network id as a string
        if (!responseJson["result"].is_null()) {
            std::string network_id_string = responseJson["result"];
            uint64_t network_id = std::stoull(network_id_string, nullptr, 10);
            if (network_id > std::numeric_limits<uint32_t>::max()) {
                throw std::runtime_error("Network ID does not fit into 32 bit unsigned integer");
            } else {
                return static_cast<uint32_t>(network_id);
            }
        }
    }

    // If we couldn't get the network ID, throw an exception
    throw std::runtime_error("Unable to get Network ID");
}

std::string Provider::evm_snapshot() {
    nlohmann::json params = nlohmann::json::array();
    cpr::Response response = makeJsonRpcRequest("evm_snapshot", params);

    if (response.status_code == 200) {
        nlohmann::json responseJson = nlohmann::json::parse(response.text);
        if (!responseJson["result"].is_null()) {
            return responseJson["result"];
        }
    }

    throw std::runtime_error("Unable to create snapshot");
}

bool Provider::evm_revert(std::string_view snapshotId) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(snapshotId);

    cpr::Response response = makeJsonRpcRequest("evm_revert", params);

    if (response.status_code == 200) {
        nlohmann::json responseJson = nlohmann::json::parse(response.text);
        return !responseJson["result"].is_null();
    }

    throw std::runtime_error("Unable to revert to snapshot");
}

uint64_t Provider::evm_increaseTime(std::chrono::seconds seconds) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(seconds.count());

    cpr::Response response = makeJsonRpcRequest("evm_increaseTime", params);
    if (response.status_code != 200) {
        throw std::runtime_error("Unable to set time");
    }
    nlohmann::json responseJson = nlohmann::json::parse(response.text);
    if (!responseJson.contains("result") && responseJson.contains("error")) {
        std::string errorMessage = "JSON RPC error: (evm_increaseTime)" + responseJson["error"]["message"].get<std::string>();
        if (responseJson["error"].contains("data") && responseJson["error"]["data"].contains("message")) {
            errorMessage += " - " + responseJson["error"]["data"]["message"].get<std::string>();
        }
        throw std::runtime_error(errorMessage);
    } else if (responseJson["result"].is_null()) {
        throw std::runtime_error("Null result in response");
    }
    response = makeJsonRpcRequest("evm_mine", nlohmann::json::array());
    if (response.status_code != 200) {
        throw std::runtime_error("Unable to set time");
    }
    nlohmann::json mineResponseJson = nlohmann::json::parse(response.text);
    if (!mineResponseJson.contains("result") && mineResponseJson.contains("error")) {
        std::string errorMessage = "JSON RPC error (evm_mine): " + mineResponseJson["error"]["message"].get<std::string>();
        if (mineResponseJson["error"].contains("data") && mineResponseJson["error"]["data"].contains("message")) {
            errorMessage += " - " + mineResponseJson["error"]["data"]["message"].get<std::string>();
        }
        throw std::runtime_error(errorMessage);
    } else if (mineResponseJson["result"].is_null()) {
        throw std::runtime_error("Null result in response");
    }
    std::string secondsHex = responseJson["result"];
    return std::stoull(secondsHex, nullptr, 16);
}


uint64_t Provider::getTransactionCount(std::string_view address, std::string_view blockTag) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(address);
    params.push_back(blockTag);

    // Make the request
    cpr::Response response = makeJsonRpcRequest("eth_getTransactionCount", params);

    if (response.status_code == 200) {
        // Parse the response
        nlohmann::json responseJson = nlohmann::json::parse(response.text);

        // Check if the result field is present and not null
        if (!responseJson["result"].is_null()) {
            // Get the transaction count
            std::string transactionCountHex = responseJson["result"];

            // Convert the transaction count from hex to decimal
            uint64_t transactionCount = std::stoull(transactionCountHex, nullptr, 16);

            // Return the transaction count
            return transactionCount;
        }
    }

    // If we couldn't get the transaction count, throw an exception
    throw std::runtime_error("Unable to get transaction count");
}

std::optional<nlohmann::json> Provider::getTransactionByHash(std::string_view transactionHash) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(transactionHash);

    // Make the request
    cpr::Response response = makeJsonRpcRequest("eth_getTransactionByHash", params);

    if (response.status_code == 200) {
        // Parse the response
        nlohmann::json responseJson = nlohmann::json::parse(response.text);

        if (responseJson.find("error") != responseJson.end())
            throw std::runtime_error("Error getting transaction: " + responseJson["error"]["message"].get<std::string>());

        // Check if the result field is present and not null
        if (!responseJson["result"].is_null()) {
            // Return the block number
            return responseJson["result"];
        }
    }

    // If we couldn't get the block number, return an empty optional
    return std::nullopt;
}

std::optional<nlohmann::json> Provider::getTransactionReceipt(std::string_view transactionHash) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(transactionHash);

    // Make the request
    cpr::Response response = makeJsonRpcRequest("eth_getTransactionReceipt", params);

    if (response.status_code == 200) {
        // Parse the response
        nlohmann::json responseJson = nlohmann::json::parse(response.text);

        if (responseJson.find("error") != responseJson.end())
            throw std::runtime_error("Error getting transaction receipt: " + responseJson["error"]["message"].get<std::string>());

        // Check if the result field is present and not null
        if (!responseJson["result"].is_null()) {
            // Return the block number
            return responseJson["result"];
        }
    }

    // If we couldn't get the block number, return an empty optional
    return std::nullopt;
}

std::vector<LogEntry> Provider::getLogs(uint64_t fromBlock, uint64_t toBlock, std::string_view address) {
    std::vector<LogEntry> logEntries;

    nlohmann::json params = nlohmann::json::array();
    nlohmann::json params_data = nlohmann::json();
    params_data["fromBlock"] = utils::decimalToHex(fromBlock, true);
    params_data["toBlock"] = utils::decimalToHex(toBlock, true);
    params_data["address"] = address;
    params.push_back(params_data);

    // Make the RPC call
    cpr::Response response = makeJsonRpcRequest("eth_getLogs", params);

    if (response.status_code == 200) {
        // Parse the response
        nlohmann::json responseJson = nlohmann::json::parse(response.text);

        if (responseJson.find("error") != responseJson.end())
            throw std::runtime_error("Error getting logs: " + responseJson["error"]["message"].get<std::string>());

        // Check if the result field is present and not null
        if (!responseJson["result"].is_null()) {
            for (const auto& logJson : responseJson["result"]) {
                LogEntry logEntry;
                logEntry.address = logJson.contains("address") ? logJson["address"].get<std::string>() : "";
                
                if (logJson.contains("topics")) {
                    for (const auto& topic : logJson["topics"]) {
                        logEntry.topics.push_back(topic.get<std::string>());
                    }
                }

                logEntry.data = logJson.contains("data") ? logJson["data"].get<std::string>() : "";
                logEntry.blockNumber = logJson.contains("blockNumber") ? std::make_optional(std::stoull(logJson["blockNumber"].get<std::string>(), nullptr, 16)) : std::nullopt;
                logEntry.transactionHash = logJson.contains("transactionHash") ? std::make_optional(logJson["transactionHash"].get<std::string>()) : std::nullopt;
                logEntry.transactionIndex = logJson.contains("transactionIndex") ? std::make_optional(std::stoull(logJson["transactionIndex"].get<std::string>(), nullptr, 16)) : std::nullopt;
                logEntry.blockHash = logJson.contains("blockHash") ? std::make_optional(logJson["blockHash"].get<std::string>()) : std::nullopt;
                logEntry.logIndex = logJson.contains("logIndex") ? std::make_optional(std::stoul(logJson["logIndex"].get<std::string>(), nullptr, 16)) : std::nullopt;
                logEntry.removed = logJson.contains("removed") ? logJson["removed"].get<bool>() : false;

                logEntries.push_back(logEntry);
            }
        }
    }
    return logEntries;
}

std::vector<LogEntry> Provider::getLogs(uint64_t block, std::string_view address) {
    return getLogs(block, block, address);
}

std::string Provider::getContractStorageRoot(std::string_view address, uint64_t blockNumberInt) {
    return getContractStorageRoot(address, utils::decimalToHex(blockNumberInt, true));
}

std::string Provider::getContractStorageRoot(std::string_view address, std::string_view blockNumber) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(address);
    auto storage_keys = nlohmann::json::array();
    params.push_back(storage_keys);
    params.push_back(blockNumber);

    auto response = makeJsonRpcRequest("eth_getProof", params);
    if(response.status_code != 200)
        throw std::runtime_error("Failed to call eth_getProof: " + response.text + " params: " + params.dump());

    nlohmann::json responseJson = nlohmann::json::parse(response.text);
    if (responseJson.find("error") != responseJson.end())
        throw std::runtime_error("Error in response of eth_getProof: " + responseJson["error"]["message"].get<std::string>());

    if (responseJson.contains("result") && responseJson["result"].contains("storageHash")) {
        return responseJson["result"]["storageHash"].get<std::string>();
    }

    throw std::runtime_error("No storage proof found in response");
}

// Calls `f()` which should return an optional<T> repeatedly (sleeping for `call_interval` between
// each call) until it returns a non-nullopt, then returns it.  Throws runtime_error on timeout.
template <typename Func>
static auto waitForResult(Func&& f, std::chrono::milliseconds timeout, const std::string& errmsg = "Transaction inclusion in a block timned out", std::chrono::milliseconds call_interval = 500ms) {
    auto timeout_at = std::chrono::steady_clock::now() + timeout;

    auto val = f();
    while (!val.has_value() && std::chrono::steady_clock::now() < timeout_at) {
        std::this_thread::sleep_for(call_interval);
        val = f();
    }

    if (val.has_value())
        return std::move(*val);

    throw std::runtime_error{errmsg};
}

// Create and send a raw transaction returns the hash but will also check that it got into the mempool
std::string Provider::sendTransaction(const Transaction& signedTx) {
    std::string hash = sendUncheckedTransaction(signedTx);

    return waitForResult([&]() -> std::optional<std::string> {
            if (getTransactionByHash(hash))
                return hash;
            return std::nullopt;
        }, 5s, "Transaction request timed out");
}

// Create and send a raw transaction returns the hash without checking if it succeeded in getting into the mempool
std::string Provider::sendUncheckedTransaction(const Transaction& signedTx) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(signedTx.serialized());
    
    auto response = makeJsonRpcRequest("eth_sendRawTransaction", params);
    if (response.status_code == 200) {
        nlohmann::json responseJson = nlohmann::json::parse(response.text);

        if (responseJson.find("error") != responseJson.end())
            throw std::runtime_error("Error sending transaction: " + responseJson["error"]["message"].get<std::string>());

        std::string hash = responseJson["result"].get<std::string>();

        return hash;
    } else {
        throw std::runtime_error("Failed to send transaction");
    }
}

uint64_t Provider::waitForTransaction(
        std::string_view txHash, std::chrono::milliseconds timeout) {
    return waitForResult(
            [&]() -> std::optional<uint64_t> {
                if (const auto maybe_tx_json = getTransactionByHash(txHash);
                    maybe_tx_json && !(*maybe_tx_json)["blockNumber"].is_null()) {

                    // Parse the block number from the hex string
                    auto blockNumberHex = (*maybe_tx_json)["blockNumber"].get<std::string_view>();
                    return utils::fromHexStringToUint64(blockNumberHex);
                }
                return std::nullopt;
            },
            timeout);
}

bool Provider::transactionSuccessful(std::string_view txHash, std::chrono::milliseconds timeout) {
    return waitForResult(
            [&]() -> std::optional<bool> {
                if (const auto maybe_tx_json = getTransactionReceipt(txHash);
                    maybe_tx_json && !(*maybe_tx_json)["status"].is_null()) {

                    // Parse the status from the hex string
                    auto statusHex = (*maybe_tx_json)["status"].get<std::string_view>();
                    return static_cast<bool>(utils::fromHexStringToUint64(statusHex));
                }
                return std::nullopt;
            },
            timeout);
}

uint64_t Provider::gasUsed(std::string_view txHash, std::chrono::milliseconds timeout) {
    return waitForResult(
            [&]() -> std::optional<uint64_t> {
                if (const auto maybe_tx_json = getTransactionReceipt(txHash);
                    maybe_tx_json && !(*maybe_tx_json)["gasUsed"].is_null()) {

                    // Parse the status from the hex string
                    auto gasUsed = (*maybe_tx_json)["gasUsed"].get<std::string_view>();
                    return utils::fromHexStringToUint64(gasUsed);
                }
                return std::nullopt;
            },
            timeout);
}

std::string Provider::getBalance(std::string_view address) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(address);
    params.push_back("latest");
    
    auto response = makeJsonRpcRequest("eth_getBalance", params);
    if (response.status_code == 200) {
        nlohmann::json responseJson = nlohmann::json::parse(response.text);

        if (responseJson.find("error") != responseJson.end())
            throw std::runtime_error("Error getting balance: " + responseJson["error"]["message"].get<std::string>());

        std::string balanceHex = responseJson["result"].get<std::string>();

        // Convert balance from hex to GMP multi-precision integer
        mpz_class balance;
        balance.set_str(balanceHex, 0); // 0 as base to automatically pick up hex from the prepended 0x of our balanceHex string

        return balance.get_str();
    } else {
        throw std::runtime_error("Failed to get balance for address " + std::string{address});
    }
}

std::string Provider::getContractDeployedInLatestBlock() {
    nlohmann::json params = nlohmann::json::array();
    params.push_back("latest");
    params.push_back(true);
    auto blockResponse = makeJsonRpcRequest("eth_getBlockByNumber", params);
    if (blockResponse.status_code != 200)
        throw std::runtime_error("Failed to get the latest block");
    nlohmann::json blockJson = nlohmann::json::parse(blockResponse.text);

    for (const auto& tx : blockJson["result"]["transactions"]) {
        std::optional<nlohmann::json> transactionReceipt = getTransactionReceipt(tx["hash"].get<std::string>());
        if (transactionReceipt.has_value())
            return transactionReceipt->at("contractAddress").get<std::string>();
    }

    throw std::runtime_error("No contracts deployed in latest block");
}


uint64_t Provider::getLatestHeight() {
    nlohmann::json params = nlohmann::json::array();
    auto blockResponse = makeJsonRpcRequest("eth_blockNumber", params);
    if (blockResponse.status_code != 200) {
        throw std::runtime_error("Failed to get the latest height");
    }
    nlohmann::json blockJson = nlohmann::json::parse(blockResponse.text);
    return std::stoull(blockJson["result"].get<std::string>(), nullptr, 16);

}

FeeData Provider::getFeeData() {
    // Get latest block
    nlohmann::json params = nlohmann::json::array();
    params.push_back("latest");
    params.push_back(true);
    auto blockResponse = makeJsonRpcRequest("eth_getBlockByNumber", params);
    if (blockResponse.status_code != 200) {
        throw std::runtime_error("Failed to call get block by number for latest block for baseFeePerGas");
    }
    nlohmann::json blockJson = nlohmann::json::parse(blockResponse.text);
    uint64_t baseFeePerGas = std::stoull(blockJson["result"]["baseFeePerGas"].get<std::string>(), nullptr, 16);
    
    // Get gas price
    params = nlohmann::json::array();
    auto gasPriceResponse = makeJsonRpcRequest("eth_gasPrice", params);
    if (gasPriceResponse.status_code != 200) {
        throw std::runtime_error("Failed to get gas price");
    }
    nlohmann::json gasPriceJson = nlohmann::json::parse(gasPriceResponse.text);
    uint64_t gasPrice = std::stoull(gasPriceJson["result"].get<std::string>(), nullptr, 16);

    // Compute maxFeePerGas and maxPriorityFeePerGas based on baseFeePerGas
    uint64_t maxPriorityFeePerGas = 3000000000;
    uint64_t maxFeePerGas = (baseFeePerGas * 2) + maxPriorityFeePerGas;

    return FeeData(gasPrice, maxFeePerGas, maxPriorityFeePerGas);
}
}; // namespace ethyl
