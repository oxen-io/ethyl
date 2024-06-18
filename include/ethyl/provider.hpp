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

using namespace std::literals;

namespace ethyl
{
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

struct Client {
    std::string name;
    cpr::Url url;
};

struct Provider : public std::enable_shared_from_this<Provider> {
    /** Add a RPC backend for interacting with the Ethereum network.
     *
     * The provider does not ensure that no duplicates are added to the list.
     *
     * @param name A label for the type of client being added. This information
     * is stored only for the user to identify the client in the list of
     * clients in a given provider.
     *
     * @returns True if the client was added successfully. False if the `url`
     * was not set.
     */
    Provider(std::chrono::milliseconds request_timeout = 3s);
    ~Provider();

    bool addClient(std::string name, std::string url);

    bool connectToNetwork();
    void disconnectFromNetwork();

    uint64_t       getTransactionCount(std::string_view address, std::string_view blockTag);
    nlohmann::json callReadFunctionJSON(const ReadCallData& callData, std::string_view blockNumber = "latest");
    std::string    callReadFunction(const ReadCallData& callData, std::string_view blockNumber = "latest");
    std::string    callReadFunction(const ReadCallData& callData, uint64_t blockNumberInt);

    uint32_t getNetworkChainId();
    std::string evm_snapshot();
    bool evm_revert(std::string_view snapshotId);

    uint64_t evm_increaseTime(std::chrono::seconds seconds);

    std::optional<nlohmann::json> getTransactionByHash(std::string_view transactionHash);
    std::optional<nlohmann::json> getTransactionReceipt(std::string_view transactionHash);
    std::vector<LogEntry> getLogs(uint64_t fromBlock, uint64_t toBlock, std::string_view address);
    std::vector<LogEntry> getLogs(uint64_t block, std::string_view address);
    std::string getContractStorageRoot(std::string_view address, uint64_t blockNumberInt);
    std::string getContractStorageRoot(std::string_view address, std::string_view blockNumber = "latest");

    std::string sendTransaction(const Transaction& signedTx);
    std::string sendUncheckedTransaction(const Transaction& signedTx);

    uint64_t waitForTransaction(std::string_view txHash, std::chrono::milliseconds timeout = 320s);
    bool transactionSuccessful(std::string_view txHash, std::chrono::milliseconds timeout = 320s);
    uint64_t gasUsed(std::string_view txHash, std::chrono::milliseconds timeout = 320s);
    std::string getBalance(std::string_view address);
    std::string getContractDeployedInLatestBlock();

    uint64_t getLatestHeight();
    FeeData getFeeData();

    /// List of clients for interacting with the Ethereum network via RPC
    /// The order of the clients dictates the order in which a request is
    /// attempted.
    std::vector<Client>                      clients;

    uint64_t next_request_id{0};
    std::map<uint64_t, std::pair<cpr::AsyncWrapper<cpr::Response>, std::function<void(std::optional<cpr::Response>)>>> pending_requests;
    std::unique_ptr<std::thread> response_thread;
    std::condition_variable response_cv;
    std::queue<uint64_t> pending_responses;
    bool running{true};

private:
    /**
     * @param timeout Set a timeout for the provider to connect to current
     * client it's attempting before returning a timeout failure. If this is not
     * set,the timeout is the default timeout value of CURL which is 300
     * seconds.
     *
     * If you have multiple clients it may be desired to set this value such
     * that the provider can quickly evaluate the backup clients in its list on
     * failure.
     */
    cpr::Response makeJsonRpcRequest(std::string_view method,
                                     const nlohmann::json& params);
    std::shared_ptr<cpr::Session> session = std::make_shared<cpr::Session>();
    std::mutex mutex;
};
}; // namespace ethyl
