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

#include <oxen/log.hpp>

#include "ethyl/provider.hpp"
#include "ethyl/utils.hpp"

#include <gmpxx.h>

namespace
{
auto logcat = oxen::log::Cat("ethyl");
}

namespace ethyl
{
namespace log = oxen::log;

template<typename T = nlohmann::json>
struct JsonResultWaiter
{
    std::promise<std::optional<T>> p;
    std::future<std::optional<T>> fut;
    JsonResultWaiter() : fut{p.get_future()} {}

    Provider::optional_callback<T> cb() {
        return [this](std::optional<T> r) {
            p.set_value(r);
        };
    }

    auto get() { return fut.get(); }
};

Provider::Provider()
{
    setTimeout(DEFAULT_TIMEOUT);
}

Provider::~Provider()
{
}

void Provider::setTimeout(std::chrono::milliseconds timeout) {
    std::lock_guard lk{mutex};
    this->request_timeout = timeout;
}

void Provider::addClient(std::string name, std::string url) {
    // TODO: actually validate the url in some meaningful way
    if (url.empty())
        throw std::invalid_argument{"Provider URL is empty."};
    std::lock_guard lk{mutex};
    if (client_sessions.contains(url))
    {
        throw std::invalid_argument{"Provider URL was already added."};
    }
    clients.emplace_back(Client{std::move(name), std::move(url)});
    client_order.push_back(clients.size() - 1);
}

size_t Provider::numClients()
{
    std::lock_guard lk{mutex};
    return clients.size();
}

std::vector<Client> Provider::getClients()
{
    std::lock_guard lk{mutex};
    return clients;
}

std::vector<size_t> Provider::getClientOrder()
{
    std::lock_guard lk{mutex};
    return client_order;
}
void Provider::setClientOrder(std::vector<size_t> order)
{
    std::lock_guard lk{mutex};
    for (auto index : order)
    {
        if (index >= clients.size())
            throw std::invalid_argument{"request client order index out of bounds"};
    }
    client_order = std::move(order);
}

std::shared_ptr<cpr::Session> Provider::get_client_session(const std::string& url)
{
    if (url.empty())
        throw std::invalid_argument{"Attempting to get session for empty URL"};

    auto& sessions = client_sessions[url];
    if (sessions.empty())
    {
        auto session = std::make_shared<cpr::Session>();
        session->SetUrl(url);
        session->SetTimeout(request_timeout);
        return session;
    }
    auto session = std::move(sessions.front());
    sessions.pop();
    session->SetTimeout(request_timeout);

    return session;
}

bool Provider::connectToNetwork() {
    // Here we can verify connection by calling some simple JSON RPC method like `net_version`
    auto result = makeJsonRpcRequest("net_version", cpr::Body("{}"));
    if (result) {
        log::debug(logcat, "Connected to the Ethereum network.");
    } else {
        log::warning(logcat, "Failed to connect to the Ethereum network.");
    }
    return bool(result);
}

void Provider::disconnectFromNetwork() {
    // TODO: Code to disconnect from Ethereum network
    log::debug(logcat, "Disconnected from the Ethereum network.");
}

std::optional<nlohmann::json> get_json_result(const cpr::Response& r)
{
    log::debug(logcat, "get_json_result");
    if (r.status_code != 200)
    {
        log::debug(logcat, "http request returned status code {} with message \"{}\"", r.status_code, r.error.message);
        return std::nullopt;
    }
    try
    {
        log::debug(logcat, "parsing json rpc result, r.text = \"{}\"", r.text);
        auto responseJson = nlohmann::json::parse(r.text);
        log::debug(logcat, "parsing json rpc result succeeded");
        if (responseJson.contains("result") and not responseJson["result"].is_null())
        {
            log::debug(logcat, "returning parsed json result");
            return std::move(responseJson["result"]);
        }
        log::warning(logcat, "json response missing \"result\" field (or is null), response: {}", responseJson.dump());
        if (auto it = responseJson.find("error"); it != responseJson.end())
        {
            log::debug(logcat, "{}", responseJson.dump());
            log::warning(logcat, "json error: {}", (*it)["message"].get<std::string_view>());
        }
    }
    catch (const std::exception& e)
    {
        log::debug(logcat, "json response failed to parse: ", e.what());
    }
    return std::nullopt;
}

void Provider::makeJsonRpcRequest(std::string_view method,
        const nlohmann::json& params,
        json_result_callback cb,
        std::forward_list<size_t> client_indices,
        bool should_try_next) {

    std::unique_lock lock{mutex};
    if (clients.empty()) {
      throw std::runtime_error(
          "No clients were set for the provider. Ensure that a client was "
          "added to the provider before issuing a request.");
    }

    if (client_indices.empty())
        client_indices = {client_order.begin(), client_order.end()};

    if (client_indices.empty())
    {
        log::warning(logcat, "attempting jsonrpc request to eth provider, but client_order is empty.  You get nothing!  You lose!  Good day, sir!");
        cb(std::nullopt);
        return;
    }

    auto client_index = client_indices.front();
    client_indices.pop_front();

    nlohmann::json bodyJson;
    bodyJson["jsonrpc"] = "2.0";
    bodyJson["method"]  = method;
    bodyJson["params"]  = params;
    bodyJson["id"]      = 1;
    log::debug(logcat, "making rpc request with body {}", bodyJson.dump());
    cpr::Body body(bodyJson.dump());
    log::debug(logcat, "cpr::Body: {}", body.str());


    if (client_index >= clients.size())
    {
        log::debug(logcat, "Attempting to use provider client with index ({}) out of bounds.", client_index);
        cb(std::nullopt);
        return;
    }
    auto url = clients[client_index].url.str();
    auto session = get_client_session(url);
    session->SetBody(body);
    session->SetHeader({{"Content-Type", "application/json"}});
    auto post_cb = [self=weak_from_this(), cb=std::move(cb), url=std::move(url), session, method, params, client_indices=std::move(client_indices), should_try_next](cpr::Response r){
        log::debug(logcat, "entering makeJsonRpcRequest PostCallback callback");

        auto ptr = self.lock();

        if (not ptr)
            return; // Provider is gone, drop response
        std::unique_lock lk{ptr->mutex};

        ptr->client_sessions.at(url).push(std::move(session));

        // TODO(doyle): It is worth it in the future to give stats on which
        // client failed and return it to the caller so that they can have some
        // mitigation strategy when a client is frequently failing.
        std::optional<nlohmann::json> result_json;
        if (result_json = get_json_result(r); result_json)
        {
            lk.unlock();
            log::debug(logcat, "makeJsonRpcRequest returning: {}", result_json->dump());
            cb(result_json);
            return;
        }

        if (should_try_next and not client_indices.empty())
        {
            lk.unlock();
            ptr->makeJsonRpcRequest(method, params, std::move(cb), std::move(client_indices), true);
            return;
        }
        cb(std::nullopt);
        return;
    };
    auto result_future = session->PostCallback(std::move(post_cb));
}

std::optional<nlohmann::json> Provider::makeJsonRpcRequest(std::string_view method,
                                 const nlohmann::json& params,
                                 std::forward_list<size_t> client_indices,
                                 bool should_try_next)
{
    JsonResultWaiter waiter;
    makeJsonRpcRequest(method, params, waiter.cb(), std::move(client_indices), should_try_next);
    return waiter.get();
}

nlohmann::json Provider::callReadFunctionJSON(const ReadCallData& callData, std::string_view blockNumber) {
    JsonResultWaiter waiter;
    callReadFunctionJSONAsync(callData, waiter.cb(), blockNumber);
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error{"Error in json rpc request \"eth_call\""};
    return *result;
}

void Provider::callReadFunctionJSONAsync(const ReadCallData& callData, json_result_callback user_cb, std::string_view blockNumber) {
    // Prepare the params for the eth_call request
    nlohmann::json params  = nlohmann::json::array();
    params[0]["to"]        = callData.contractAddress;
    params[0]["data"]      = callData.data;
    params[1]              = blockNumber; // use the provided block number or default to "latest"

    makeJsonRpcRequest("eth_call", params, std::move(user_cb));
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
    JsonResultWaiter<uint32_t> waiter;
    getNetworkChainIdAsync(waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Unable to get Network ID");
    return *result;
}

void Provider::getNetworkChainIdAsync(optional_callback<uint32_t> user_cb)
{
    nlohmann::json params = nlohmann::json::array();
    auto cb = [user_cb=std::move(user_cb)](std::optional<nlohmann::json> r) {
        if (!r)
        {
            user_cb(std::nullopt);
            return;
        }

        uint64_t network_id;
        if (utils::parseInt(r->get<std::string>(), network_id))
        {
            if (network_id > std::numeric_limits<uint32_t>::max()) {
                log::warning(logcat, "Network ID ({}) does not fit into 32 bit unsigned integer", network_id);
                user_cb(std::nullopt);
                return;
            }
            user_cb(static_cast<uint32_t>(network_id));
            return;
        }
        log::warning(logcat, "Failed to parse Network ID from json rpc response.");
        user_cb(std::nullopt);
    };
    makeJsonRpcRequest("net_version", params, std::move(cb));
}

std::string Provider::evm_snapshot() {
    JsonResultWaiter waiter;
    evm_snapshot_async(waiter.cb());
    auto result = waiter.get();
    if (!result)
        throw std::runtime_error("Unable to create snapshot");
    return *result;
}

void Provider::evm_snapshot_async(json_result_callback cb) {
    nlohmann::json params = nlohmann::json::array();
    makeJsonRpcRequest("evm_snapshot", params, std::move(cb));
}

bool Provider::evm_revert(std::string_view snapshotId) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(snapshotId);

    JsonResultWaiter waiter;
    makeJsonRpcRequest("evm_revert", params, waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Unable to revert to snapshot");
    return true;
}

uint64_t Provider::evm_increaseTime(std::chrono::seconds seconds) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(seconds.count());

    JsonResultWaiter waiter;
    makeJsonRpcRequest("evm_increaseTime", params, waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Unable to set time");

    JsonResultWaiter waiter2;
    makeJsonRpcRequest("evm_mine", nlohmann::json::array(), waiter2.cb());
    result = waiter2.get();
    if (!result)
        throw std::runtime_error("Unable to set time");

    std::string secondsHex = *result;
    return std::stoull(secondsHex, nullptr, 16);
}


uint64_t Provider::getTransactionCount(std::string_view address, std::string_view blockTag) {
    JsonResultWaiter<uint64_t> waiter;
    getTransactionCountAsync(address, blockTag, waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Unable to get transaction count");
    return *result;
}

void Provider::getTransactionCountAsync(std::string_view address, std::string_view blockTag, optional_callback<uint64_t> user_cb)
{
    nlohmann::json params = nlohmann::json::array();
    params.push_back(address);
    params.push_back(blockTag);

    auto cb = [user_cb=std::move(user_cb)](std::optional<nlohmann::json> r) {
        if (!r)
        {
            user_cb(std::nullopt);
            return;
        }

        try
        {
            uint64_t tx_count = utils::hexStringToU64(r->get<std::string>());
            user_cb(tx_count);
            return;
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Failed to parse transaction count from json rpc response: {}", e.what());
            user_cb(std::nullopt);
        }
    };
    makeJsonRpcRequest("eth_getTransactionCount", params, std::move(cb));
}

std::optional<nlohmann::json> Provider::getTransactionByHash(std::string_view transactionHash) {
    JsonResultWaiter waiter;
    getTransactionByHashAsync(transactionHash, waiter.cb());
    return waiter.get();
}

void Provider::getTransactionByHashAsync(std::string_view transactionHash, json_result_callback cb)
{
    nlohmann::json params = nlohmann::json::array();
    params.push_back(transactionHash);
    makeJsonRpcRequest("eth_getTransactionByHash", params, std::move(cb));
}

std::optional<nlohmann::json> Provider::getTransactionReceipt(std::string_view transactionHash) {
    JsonResultWaiter waiter;
    getTransactionReceiptAsync(transactionHash, waiter.cb());
    return waiter.get();
}

void Provider::getTransactionReceiptAsync(std::string_view transactionHash, json_result_callback cb)
{
    nlohmann::json params = nlohmann::json::array();
    params.push_back(transactionHash);

    makeJsonRpcRequest("eth_getTransactionReceipt", params, cb);
}

std::vector<LogEntry> Provider::getLogs(uint64_t fromBlock, uint64_t toBlock, std::string_view address) {
    JsonResultWaiter<std::vector<LogEntry>> waiter;
    getLogsAsync(fromBlock, toBlock, address, waiter.cb());
    auto result = waiter.get();
    if (!result)
        throw std::runtime_error("Error in json rpc eth_getLogs");
    return *result;
}

std::vector<LogEntry> Provider::getLogs(uint64_t block, std::string_view address) {
    return getLogs(block, block, address);
}

void Provider::getLogsAsync(uint64_t fromBlock, uint64_t toBlock, std::string_view address, optional_callback<std::vector<LogEntry>> user_cb)
{
    nlohmann::json params = nlohmann::json::array();
    nlohmann::json params_data = nlohmann::json();
    params_data["fromBlock"] = utils::decimalToHex(fromBlock, true);
    params_data["toBlock"] = utils::decimalToHex(toBlock, true);
    params_data["address"] = address;
    params.push_back(params_data);

    auto cb = [user_cb=std::move(user_cb)](std::optional<nlohmann::json> r) {
        if (!r)
        {
            user_cb(std::nullopt);
            return;
        }
            
        nlohmann::json responseJson = *r;

        std::vector<LogEntry> logEntries;
        for (const auto& logJson : responseJson) {
            try
            {
                LogEntry logEntry;
                logEntry.address = logJson.contains("address") ? logJson["address"].get<std::string>() : "";

                if (logJson.contains("topics")) {
                    for (const auto& topic : logJson["topics"]) {
                        logEntry.topics.push_back(topic.get<std::string>());
                    }
                }

                logEntry.data = logJson.contains("data") ? logJson["data"].get<std::string>() : "";
                logEntry.blockNumber = logJson.contains("blockNumber") ? std::make_optional(utils::hexStringToU64(logJson["blockNumber"].get<std::string>())) : std::nullopt;
                logEntry.transactionHash = logJson.contains("transactionHash") ? std::make_optional(logJson["transactionHash"].get<std::string>()) : std::nullopt;
                logEntry.transactionIndex = logJson.contains("transactionIndex") ? std::make_optional(utils::hexStringToU64(logJson["transactionIndex"].get<std::string>())) : std::nullopt;
                logEntry.blockHash = logJson.contains("blockHash") ? std::make_optional(logJson["blockHash"].get<std::string>()) : std::nullopt;

                if (logJson.contains("logIndex"))
                {
                    uint64_t log_index;
                    if (!utils::parseInt(logJson["logIndex"].get<std::string>(), log_index))
                        throw std::runtime_error{"Error parsing logIndex element as uint64_t"};
                    if (log_index > std::numeric_limits<uint32_t>::max())
                        throw std::runtime_error{"Error logIndex element > uint32_t max"};
                    logEntry.logIndex = static_cast<uint32_t>(log_index);
                }
                else
                    logEntry.logIndex = std::nullopt;

                logEntry.removed = logJson.contains("removed") ? logJson["removed"].get<bool>() : false;

                logEntries.push_back(logEntry);
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Error parsing response from eth_getLogs: {}", e.what());
                user_cb(std::nullopt);
                return;
            }
        }
        user_cb(std::move(logEntries));
    };
    makeJsonRpcRequest("eth_getLogs", params, cb);
}
void Provider::getLogsAsync(uint64_t block, std::string_view address, optional_callback<std::vector<LogEntry>> cb)
{
    getLogsAsync(block, block, address, std::move(cb));
}

std::string Provider::getContractStorageRoot(std::string_view address, uint64_t blockNumberInt) {
    return getContractStorageRoot(address, utils::decimalToHex(blockNumberInt, true));
}

std::string Provider::getContractStorageRoot(std::string_view address, std::string_view blockNumber) {
    JsonResultWaiter<std::string> waiter;
    getContractStorageRootAsync(address, waiter.cb(), blockNumber);
    auto result = waiter.get();
    if (!result)
        throw std::runtime_error("json rpc storageRoot failed");
    return *result;
}

void Provider::getContractStorageRootAsync(std::string_view address, optional_callback<std::string> user_cb, uint64_t blockNumberInt)
{
    getContractStorageRootAsync(address, std::move(user_cb), utils::decimalToHex(blockNumberInt, true));
}
void Provider::getContractStorageRootAsync(std::string_view address, optional_callback<std::string> user_cb, std::string_view blockNumber)
{
    nlohmann::json params = nlohmann::json::array();
    params.push_back(address);
    auto storage_keys = nlohmann::json::array();
    params.push_back(storage_keys);
    params.push_back(blockNumber);

    auto cb = [user_cb=std::move(user_cb)](std::optional<nlohmann::json> r) {
        if (!r)
        {
            user_cb(std::nullopt);
            return;
        }
            
        nlohmann::json responseJson = *r;
        if (!responseJson.contains("storageHash"))
        {
            log::warning(logcat, "eth_getProof result did not contain key storageHash");
            user_cb(std::nullopt);
            return;
        }
        user_cb(responseJson["storageHash"]);
    };
    makeJsonRpcRequest("eth_getProof", params, std::move(cb));
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
    JsonResultWaiter waiter;
    sendUncheckedTransactionAsync(signedTx, waiter.cb());
    auto result = waiter.get();
    if (!result)
        throw std::runtime_error("Failed to send transaction");
    return *result;
}

void Provider::sendUncheckedTransactionAsync(const Transaction& signedTx, optional_callback<std::string> user_cb)
{
    nlohmann::json params = nlohmann::json::array();
    params.push_back("0x" + signedTx.serializeAsHex());

    makeJsonRpcRequest("eth_sendRawTransaction", params, std::move(user_cb));
}

uint64_t Provider::waitForTransaction(
        std::string_view txHash, std::chrono::milliseconds timeout) {
    return waitForResult(
            [&]() -> std::optional<uint64_t> {
                if (const auto maybe_tx_json = getTransactionByHash(txHash);
                    maybe_tx_json && !(*maybe_tx_json)["blockNumber"].is_null()) {

                    // Parse the block number from the hex string
                    auto blockNumberHex = (*maybe_tx_json)["blockNumber"].get<std::string_view>();
                    return utils::hexStringToU64(blockNumberHex);
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
                    return static_cast<bool>(utils::hexStringToU64(statusHex));
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
                    return utils::hexStringToU64(gasUsed);
                }
                return std::nullopt;
            },
            timeout);
}

std::string Provider::getBalance(std::string_view address) {
    JsonResultWaiter waiter;
    getBalanceAsync(address, waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Failed to get balance for address " + std::string{address});
    return *result;
}

void Provider::getBalanceAsync(std::string_view address, optional_callback<std::string> user_cb)
{
    nlohmann::json params = nlohmann::json::array();
    params.push_back(address);
    params.push_back("latest");

    auto cb = [user_cb=std::move(user_cb)](std::optional<nlohmann::json> r) {
        if (!r)
        {
            user_cb(std::nullopt);
            return;
        }

        try
        {
            std::string balanceHex = r->get<std::string>();

            // Convert balance from hex to GMP multi-precision integer
            mpz_class balance;
            balance.set_str(balanceHex, 0); // 0 as base to automatically pick up hex from the prepended 0x of our balanceHex string

            user_cb(balance.get_str());
            return;
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "eth_getBalance response, failed to parse bigint: {}", r->get<std::string>());
            user_cb(std::nullopt);
        }
    };
    makeJsonRpcRequest("eth_getBalance", params, std::move(cb));
}

std::string Provider::getContractDeployedInLatestBlock() {
    nlohmann::json params = nlohmann::json::array();
    params.push_back("latest");
    params.push_back(true);
    JsonResultWaiter waiter;
    makeJsonRpcRequest("eth_getBlockByNumber", params, waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Failed to get the latest block");

    nlohmann::json blockJson = *result;
    for (const auto& tx : blockJson["result"]["transactions"]) {
        std::optional<nlohmann::json> transactionReceipt = getTransactionReceipt(tx["hash"].get<std::string>());
        if (transactionReceipt.has_value())
            return transactionReceipt->at("contractAddress").get<std::string>();
    }

    throw std::runtime_error("No contracts deployed in latest block");
}

std::optional<uint64_t> parseHeightResponse(const std::optional<nlohmann::json>& r)
{
    if (!r)
    {
        log::debug(logcat, "eth_blockNumber result empty");
        return std::nullopt;
    }
    log::debug(logcat, "eth_blockNumber result: {}", r->dump());

    try
    {
        uint64_t height = utils::hexStringToU64(r->get<std::string>());
        return height;
    }
    catch (const std::exception& e)
    {
        log::warning(logcat, "Error parsing response from eth_blockNumber, input: {}", r->get<std::string>());
        return std::nullopt;
    }
}

uint64_t Provider::getLatestHeight() {
    JsonResultWaiter waiter;
    getLatestHeightAsync(waiter.cb());
    auto result = waiter.get();
        throw std::runtime_error("Failed to get the latest height");
    return *result;

}

void Provider::getLatestHeightAsync(optional_callback<uint64_t> user_cb)
{
    nlohmann::json params = nlohmann::json::array();

    auto cb = [user_cb=std::move(user_cb)](std::optional<nlohmann::json> r) {
        auto height = parseHeightResponse(r);
        if (!height)
            user_cb(std::nullopt);
        user_cb(height);
    };

    makeJsonRpcRequest("eth_blockNumber", params, std::move(cb));
}

std::vector<HeightInfo> Provider::getAllHeights()
{
    JsonResultWaiter<std::vector<HeightInfo>> waiter;
    std::promise<std::vector<HeightInfo>> p;
    auto fut = p.get_future();
    auto cb = [&p](std::vector<HeightInfo> r) {
        p.set_value(r);
    };
    getAllHeightsAsync(std::move(cb));
    return fut.get();
}

void Provider::getAllHeightsAsync(std::function<void(std::vector<HeightInfo>)> user_cb)
{
    std::lock_guard lk{mutex};

    struct full_request {
        std::vector<HeightInfo> infos;
        std::atomic<size_t> done_count{0};
        std::function<void(std::vector<HeightInfo>)> user_cb;
    };

    auto req = std::make_shared<full_request>();
    req->infos.resize(clients.size());
    req->user_cb = std::move(user_cb);

    for (size_t i=0; i < clients.size(); i++)
    {
        req->infos[i].index = i;
        auto cb = [i, req](std::optional<nlohmann::json> r){
            auto height = parseHeightResponse(r);
            if (height)
            {
                req->infos[i].height = *height;
                req->infos[i].success = true;
            }
            if (++(req->done_count) == req->infos.size())
            {
                (req->user_cb)(std::move(req->infos));
            }
        };
        makeJsonRpcRequest("eth_blockNumber", nlohmann::json::array(), std::move(cb), {i}, false);
    }
}

FeeData Provider::getFeeData() {
    // Get latest block
    nlohmann::json params = nlohmann::json::array();
    params.push_back("latest");
    params.push_back(true);

    JsonResultWaiter waiter;
    makeJsonRpcRequest("eth_getBlockByNumber", params, waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Failed to get eth_getBlockByNumber");

    auto gas_fee_str = (*result)["baseFeePerGas"].get<std::string>();
    uint64_t baseFeePerGas = utils::hexStringToU64(gas_fee_str);
    
    params = nlohmann::json::array();
    JsonResultWaiter waiter2;
    makeJsonRpcRequest("eth_gasPrice", params, waiter2.cb());
    result = waiter2.get();
    if (!result)
        throw std::runtime_error("Failed to get eth_gasPrice");

    uint64_t gasPrice = utils::hexStringToU64(result->get<std::string>());

    // Compute maxFeePerGas and maxPriorityFeePerGas based on baseFeePerGas
    uint64_t maxPriorityFeePerGas = 3000000000;
    uint64_t maxFeePerGas = (baseFeePerGas * 2) + maxPriorityFeePerGas;

    return FeeData(gasPrice, maxFeePerGas, maxPriorityFeePerGas);
}

}; // namespace ethyl
