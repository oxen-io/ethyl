// logs.hpp
#pragma once

#include <string>
#include <vector>
#include <optional>

namespace ethyl
{
struct LogEntry {
    std::string address; // Address from which this log originated
    std::vector<std::string> topics; // Array of 0-4 32-byte data of indexed log arguments
    std::string data; // One or more 32-byte non-indexed arguments of the log
    std::optional<uint64_t> blockNumber; // Block number where this log was in (optional)
    std::optional<std::string> transactionHash; // Hash of the transaction this log was created from (optional)
    std::optional<uint32_t> transactionIndex; // Index of the transaction in the block (optional)
    std::optional<std::string> blockHash; // Hash of the block where this log was in (optional)
    std::optional<uint32_t> logIndex; // Index of the log in the block (optional)
    bool removed; // True if log was removed due to a chain reorganization
};
}  // namespace ethyl
