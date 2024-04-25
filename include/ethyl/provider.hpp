// Provider.hpp
#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <chrono>
#include <mutex>

#include <cpr/cprtypes.h>
#include <cpr/session.h>
#include <nlohmann/json_fwd.hpp>

#include "transaction.hpp"
#include "logs.hpp"

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
    std::mutex mutex;
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

    uint64_t evm_increaseTime(std::chrono::seconds seconds);

    std::optional<nlohmann::json> getTransactionByHash(const std::string& transactionHash);
    std::optional<nlohmann::json> getTransactionReceipt(const std::string& transactionHash);
    std::vector<LogEntry> getLogs(uint64_t fromBlock, uint64_t toBlock, const std::string& address);
    std::vector<LogEntry> getLogs(uint64_t block, const std::string& address);
    std::string getContractStorageRoot(const std::string& address, uint64_t blockNumberInt);
    std::string getContractStorageRoot(const std::string& address, const std::string& blockNumber = "latest");

    std::string sendTransaction(const Transaction& signedTx);
    std::string sendUncheckedTransaction(const Transaction& signedTx);

    uint64_t waitForTransaction(const std::string& txHash, int64_t timeout = 320000);
    bool transactionSuccessful(const std::string& txHash, int64_t timeout = 320000);
    uint64_t gasUsed(const std::string& txHash, int64_t timeout = 320000);
    std::string getBalance(const std::string& address);
    std::string getContractDeployedInLatestBlock();

    uint64_t getLatestHeight();
    FeeData getFeeData();

private:
    cpr::Response makeJsonRpcRequest(const std::string& method, const nlohmann::json& params);
};

