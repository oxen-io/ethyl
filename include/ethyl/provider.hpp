// Provider.hpp
#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <chrono>

#include <cpr/cpr.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

#include "transaction.hpp"

struct ReadCallData {
    std::string contractAddress;
    std::string data;
};

struct FeeData {
    uint64_t gasPrice;
    uint64_t maxFeePerGas;
    uint64_t maxPriorityFeePerGas;

    FeeData(uint64_t _gasPrice, uint64_t _maxFeePerGas, uint64_t _maxPriorityFeePerGas)
        : gasPrice(_gasPrice), maxFeePerGas(_maxFeePerGas), maxPriorityFeePerGas(_maxPriorityFeePerGas) {}
};

class Provider {
    std::string clientName;
    cpr::Url url;
    cpr::Session session;
public:
    Provider(const std::string& name, const std::string& _url);
    ~Provider();

    void connectToNetwork();
    void disconnectFromNetwork();

    uint64_t       getTransactionCount(const std::string& address, const std::string& blockTag);
    nlohmann::json callReadFunctionJSON(const ReadCallData& callData, std::string_view blockNumber = "latest");
    std::string    callReadFunction(const ReadCallData& callData, std::string_view blockNumber = "latest");
    std::string    callReadFunction(const ReadCallData& callData, uint64_t blockNumberInt);

    uint32_t getNetworkChainId();
    std::string evm_snapshot();
    bool evm_revert(const std::string& snapshotId);

    template <typename Rep, typename Period>
    uint64_t evm_increaseTime(const std::chrono::duration<Rep, Period>& duration) {
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();

        nlohmann::json params = nlohmann::json::array();
        params.push_back(seconds);

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

    std::optional<nlohmann::json> getTransactionByHash(const std::string& transactionHash);
    std::optional<nlohmann::json> getTransactionReceipt(const std::string& transactionHash);

    std::string sendTransaction(const Transaction& signedTx);
    std::string sendUncheckedTransaction(const Transaction& signedTx);

    uint64_t waitForTransaction(const std::string& txHash, int64_t timeout = 320000);
    bool transactionSuccessful(const std::string& txHash, int64_t timeout = 320000);
    uint64_t gasUsed(const std::string& txHash, int64_t timeout = 320000);
    std::string getBalance(const std::string& address);
    std::string getContractDeployedInLatestBlock();

    FeeData getFeeData();

private:
    cpr::Response makeJsonRpcRequest(const std::string& method, const nlohmann::json& params);
};

