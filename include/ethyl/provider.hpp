// Provider.hpp
#pragma once

#include <string>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

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

    uint64_t getTransactionCount(const std::string& address, const std::string& blockTag);
    std::string callReadFunction(const ReadCallData& callData);
    uint32_t getNetworkChainId();
    std::optional<nlohmann::json> getTransactionByHash(const std::string& transactionHash);
    std::optional<nlohmann::json> getTransactionReceipt(const std::string& transactionHash);

    std::string sendTransaction(const Transaction& signedTx);
    std::string sendUncheckedTransaction(const Transaction& signedTx);

    uint64_t waitForTransaction(const std::string& txHash, int64_t timeout = 320000);
    bool transactionSuccessful(const std::string& txHash, int64_t timeout = 320000);
    uint64_t gasUsed(const std::string& txHash, int64_t timeout = 320000);
    uint64_t getBalance(const std::string& address);

    FeeData getFeeData();

private:
    cpr::Response makeJsonRpcRequest(const std::string& method, const nlohmann::json& params);
};

