// provider.cpp
#include <chrono>
#include <thread>

#pragma GCC diagnostic push
#ifndef __clang__
#pragma GCC diagnostic ignored "-Wuseless-cast"
#pragma GCC diagnostic ignored "-Wconversion"
#endif
#include <nlohmann/json.hpp>
#include <cpr/cpr.h>
#pragma GCC diagnostic pop

#include <oxen/log.hpp>

#include "ethyl/provider.hpp"
#include "ethyl/utils.hpp"

#include <gmp.h>

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
            p.set_value(std::move(r));
        };
    }

    auto get() { return fut.get(); }
};

Provider::Provider()
{
    setTimeout(DEFAULT_TIMEOUT);
}

void Provider::setTimeout(std::chrono::milliseconds timeout) {
    std::lock_guard lk{mutex};
    request_timeout = timeout;
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
    // Here we can verify connection by calling some simple JSON RPC method like `eth_chainId`
    auto result = makeJsonRpcRequest("eth_chainId", nlohmann::json::array());
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
        lock.unlock();
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
    cpr::Body body(bodyJson.dump());
    log::debug(logcat, "making rpc request with body {}", body.data());

    if (client_index >= clients.size())
    {
        lock.unlock();
        log::debug(logcat, "Attempting to use provider client with index ({}) out of bounds.", client_index);
        cb(std::nullopt);
        return;
    }
    auto url = clients[client_index].url;
    auto session = get_client_session(url);
    session->SetBody(body);
    session->SetHeader({{"Content-Type", "application/json"}});
    auto post_cb = [self=weak_from_this(), cb=std::move(cb), url=std::move(url), session, method, params, client_indices=std::move(client_indices), should_try_next](cpr::Response r){
        log::trace(logcat, "entering makeJsonRpcRequest PostCallback callback");

        auto ptr = self.lock();

        if (not ptr)
            return; // Provider is gone, drop response

        {
            std::unique_lock lk{ptr->mutex};
            ptr->client_sessions.at(url).push(std::move(session));
        }

        // TODO(doyle): It is worth it in the future to give stats on which
        // client failed and return it to the caller so that they can have some
        // mitigation strategy when a client is frequently failing.
        std::optional<nlohmann::json> result_json;
        if (result_json = get_json_result(r); result_json)
        {
#ifndef NDEBUG
            log::debug(logcat, "makeJsonRpcRequest returning: {}", result_json->dump());
#endif
            cb(result_json);
            return;
        }

        if (should_try_next and not client_indices.empty())
        {
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

nlohmann::json Provider::callReadFunctionJSON(
        std::string_view address, std::string_view data, std::string_view blockNumber) {
    JsonResultWaiter waiter;
    callReadFunctionJSONAsync(address, data, waiter.cb(), blockNumber);
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error{"Error in json rpc request \"eth_call\""};
    return *result;
}

void Provider::callReadFunctionJSONAsync(
        std::string_view address,
        std::string_view data,
        json_result_callback user_cb,
        std::string_view blockNumber) {
    makeJsonRpcRequest(
            "eth_call",
            nlohmann::json{{{"to", address}, {"data", data}}, blockNumber},
            std::move(user_cb));
}

std::string Provider::callReadFunction(
        std::string_view address, std::string_view data, std::string_view blockNumber) {
    return callReadFunctionJSON(address, data, blockNumber).get<std::string>();
}

std::string Provider::callReadFunction(
        std::string_view address, std::string_view data, uint64_t blockNumber) {
    return callReadFunction(address, data, utils::decimalToHex(blockNumber, true));
}

uint64_t Provider::getChainId() {
    JsonResultWaiter<uint64_t> waiter;
    getChainIdAsync(waiter.cb());
    auto result = waiter.get();

    if (!result)
        throw std::runtime_error("Unable to get Network ID");
    return *result;
}

static std::optional<uint64_t> parseHexNumResponse(
        const std::optional<nlohmann::json>& r, std::string_view endpoint) {
    if (!r) {
        log::debug(logcat, "{} result empty", endpoint);
        return std::nullopt;
    }
#ifndef NDEBUG
    log::debug(logcat, "{} result: {}", endpoint, r->dump());
#endif

    try {
        return utils::hexStringToU64(r->get<std::string_view>());
    } catch (const std::exception& e) {
        log::warning(
                logcat,
                "Error parsing response from {}, input: {}: {}",
                endpoint,
                r->dump(),
                e.what());
        return std::nullopt;
    }
}

void Provider::getChainIdAsync(optional_callback<uint64_t> user_cb) {
    makeJsonRpcRequest(
            "eth_chainId",
            nlohmann::json::array(),
            [user_cb = std::move(user_cb)](std::optional<nlohmann::json> r) {
                user_cb(parseHexNumResponse(r, "eth_chainId"));
            });
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

bool Provider::evm_setAutomine(bool enable) {
    nlohmann::json params = nlohmann::json::array();
    params.push_back(enable);
    std::optional<nlohmann::json> result = makeJsonRpcRequest("evm_setAutomine", params);
    return result.has_value();
}

bool Provider::evm_mine() {
    std::optional<nlohmann::json> result = makeJsonRpcRequest("evm_mine", nlohmann::json::array());
    return result.has_value();
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

template <typename T = std::string>
static std::optional<T> maybe_get(const nlohmann::json& e, const std::string& key) {
    std::optional<T> result;
    if (auto it = e.find(key); it != e.end() && !it->is_null())
        it->get_to(result.emplace());
    return result;
}

static std::optional<uint64_t> maybe_get_u64_hex(const nlohmann::json& e, const std::string& key) {
    std::optional<uint64_t> result;
    if (auto result_hex = maybe_get(e, key))
        result = utils::hexStringToU64(*result_hex);
    return result;
}

static std::optional<uint32_t> maybe_get_u32_hex(const nlohmann::json& e, const std::string& key) {
    std::optional<uint32_t> result;
    if (auto val = maybe_get_u64_hex(e, key)) {
        if (*val > std::numeric_limits<uint32_t>::max())
            throw std::runtime_error{"Error " + key + " value > uint32_t max"};
        result = static_cast<uint32_t>(*val);
    }
    return result;
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
                logEntry.address = logJson.at("address").get<std::string>();
                if (auto it = logJson.find("topics"); it != logJson.end())
                    it->get_to(logEntry.topics);
                logJson.at("data").get_to(logEntry.data);
                logEntry.blockNumber = maybe_get_u64_hex(logJson, "blockNumber");
                logEntry.transactionHash = maybe_get(logJson, "transactionHash");
                logEntry.transactionIndex = maybe_get_u32_hex(logJson, "transactionIndex");
                logEntry.blockHash = maybe_get(logJson, "blockHash");
                logEntry.logIndex = maybe_get_u32_hex(logJson, "logIndex");
                logEntry.removed = maybe_get<bool>(logJson, "removed").value_or(false);

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

        std::string balanceHex = r->get<std::string>();

        // Convert balance from hex to GMP multi-precision integer

        std::optional<std::string> bal10;
        mpz_t balance;
        // 0 as base to automatically pick up hex from the prepended 0x of our balanceHex string
        if (int rc = mpz_init_set_str(balance, balanceHex.c_str(), 0); rc == 0) {
            bal10.emplace();
            bal10->resize(mpz_sizeinbase(balance, 10) + 1);
            mpz_get_str(bal10->data(), 10, balance);
            bal10->resize(std::strlen(bal10->c_str()));
        } else {
            log::warning(logcat, "eth_getBalance response, failed to parse bigint: {}", balanceHex);
        }
        mpz_clear(balance);
        user_cb(std::move(bal10));
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
    for (const auto& tx : blockJson["transactions"]) {
        std::optional<nlohmann::json> transactionReceipt = getTransactionReceipt(tx["hash"].get<std::string>());
        if (transactionReceipt.has_value())
            return transactionReceipt->at("contractAddress").get<std::string>();
    }

    throw std::runtime_error("No contracts deployed in latest block");
}

uint64_t Provider::getLatestHeight() {
    JsonResultWaiter waiter;
    getLatestHeightAsync(waiter.cb());
    auto result = waiter.get();
    if (!result)
        throw std::runtime_error("Failed to get the latest height");
    return *result;

}

void Provider::getLatestHeightAsync(optional_callback<uint64_t> user_cb)
{
    nlohmann::json params = nlohmann::json::array();

    auto cb = [user_cb=std::move(user_cb)](std::optional<nlohmann::json> r) {
        auto height = parseHexNumResponse(r, "eth_blockNumber");
        user_cb(height);
    };

    makeJsonRpcRequest("eth_blockNumber", params, std::move(cb));
}

std::vector<HeightInfo> Provider::getAllHeights() {
    std::promise<std::vector<HeightInfo>> p;
    getAllHeightsAsync([&p](std::vector<HeightInfo> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
}

std::vector<ChainIdInfo> Provider::getAllChainIds() {
    std::promise<std::vector<ChainIdInfo>> p;
    getAllChainIdsAsync([&p](std::vector<ChainIdInfo> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
}

namespace {

    template <typename T>
    struct full_request {
        std::atomic<size_t> remaining;
        std::function<void(std::vector<T>)> user_cb;
        std::vector<T> result;

        explicit full_request(size_t count, std::function<void(std::vector<T>)> cb) :
                remaining{count}, user_cb{std::move(cb)} {
            result.resize(count);
        }

        void done() {
            assert(remaining);
            if (!--remaining)
                user_cb(std::move(result));
        }
    };

}  // namespace

void Provider::getAllHeightsAsync(std::function<void(std::vector<HeightInfo>)> user_cb) {
    auto clients = numClients();
    if (clients == 0)
        return user_cb(std::vector<HeightInfo>{});
    auto req = std::make_shared<full_request<HeightInfo>>(numClients(), std::move(user_cb));

    for (size_t i = 0; i < req->result.size(); i++) {
        req->result[i].index = i;
        auto cb = [&info = req->result[i], req](std::optional<nlohmann::json> r) mutable {
            if (auto height = parseHexNumResponse(r, "eth_blockNumber")) {
                info.height = *height;
                info.success = true;
            }
            req->done();
        };
        makeJsonRpcRequest("eth_blockNumber", nlohmann::json::array(), std::move(cb), {i}, false);
    }
}

void Provider::getAllChainIdsAsync(std::function<void(std::vector<ChainIdInfo>)> user_cb) {
    auto clients = numClients();
    if (clients == 0)
        return user_cb(std::vector<ChainIdInfo>{});
    auto req = std::make_shared<full_request<ChainIdInfo>>(clients, std::move(user_cb));

    for (size_t i = 0; i < req->result.size(); i++) {
        req->result[i].index = i;
        auto cb = [&info = req->result[i], req](std::optional<nlohmann::json> r) mutable {
            if (auto chainid = parseHexNumResponse(r, "eth_chainId")) {
                info.chainId = *chainid;
                info.success = true;
            }
            req->done();
        };
        makeJsonRpcRequest("eth_chainId", nlohmann::json::array(), std::move(cb), {i}, false);
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

} // namespace ethyl
