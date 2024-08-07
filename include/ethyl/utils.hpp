#pragma once

#include <charconv>
#include <cstdint>
#include <span>
#include <string>
#include <array>
#include <vector>

#include <oxenc/common.h>
#include <oxenc/hex.h>

namespace ethyl
{
using ECDSACompactSignature = std::array<unsigned char, 64 + 1 /*recovery id*/>;
using Bytes20 = std::array<unsigned char, 20>;
using Bytes32 = std::array<unsigned char, 32>;

namespace utils
{
    enum class PaddingDirection {
        LEFT,
        RIGHT
    };

    std::string      decimalToHex(uint64_t decimal, bool prefixed_0x = false);
    std::string_view trimPrefix(std::string_view src, std::string_view prefix);
    std::string_view trimLeadingZeros(std::string_view src);

    using oxenc::basic_char;
    template <basic_char Char = unsigned char>
    std::vector<Char> fromHexString(std::string_view hexStr) {
        hexStr = trimPrefix(hexStr, "0x");
        hexStr = trimPrefix(hexStr, "0X");

        if (!oxenc::is_hex(hexStr))
            throw std::invalid_argument{"input string is not hex"};

        std::vector<Char> result;
        result.reserve(oxenc::from_hex_size(hexStr.size()));
        oxenc::from_hex(hexStr.begin(), hexStr.end(), std::back_inserter(result));
        return result;
    }
    extern template std::vector<char> fromHexString<char>(std::string_view);
    extern template std::vector<unsigned char> fromHexString<unsigned char>(std::string_view);

    template <basic_char Char = unsigned char>
    std::array<Char, 32> fromHexString32Byte(std::string_view hexStr) {
        hexStr = trimPrefix(hexStr, "0x");

        if (!oxenc::is_hex(hexStr) || hexStr.size() != 64) {
            throw std::invalid_argument("Input string length should be 64 hex characters for 32 bytes");
        }

        std::array<Char, 32> bytesArr;
        oxenc::from_hex(hexStr.begin(), hexStr.end(), bytesArr.begin());

        return bytesArr;
    }
    extern template std::array<char, 32> fromHexString32Byte<char>(std::string_view);
    extern template std::array<unsigned char, 32> fromHexString32Byte<unsigned char>(std::string_view);

    uint64_t hexStringToU64(std::string_view hexStr);

    std::string padToNBytes(std::string_view hexInput, size_t bytes, PaddingDirection direction = PaddingDirection::LEFT);

    inline std::string padTo8Bytes(std::string_view hexInput, PaddingDirection direction = PaddingDirection::LEFT) {
        return padToNBytes(hexInput, 8, direction);
    }

    inline std::string padTo32Bytes(std::string_view hexInput, PaddingDirection direction = PaddingDirection::LEFT) {
        return padToNBytes(hexInput, 32, direction);
    }

    /// Parses an integer of some sort from a string, requiring that the entire
    /// string be consumed during parsing.  Return false if parsing failed, sets
    /// `value` and returns true if the entire string was consumed.
    template <typename T>
    bool parseInt(const std::string_view str, T& value, int base = 10) {
        T tmp;
        auto* strend = str.data() + str.size();
        auto [p, ec] = std::from_chars(str.data(), strend, tmp, base);
        if (ec != std::errc() || p != strend)
            return false;
        value = tmp;
        return true;
    }

    /// Hashes a hex string into a 32-byte hash using keccak by first converting
    /// the hex to bytes. The hex string is allowed to start with '0x' and '0X'.
    /// Passing bytes to this function will throw an `invalid_argument`
    /// exception.
    Bytes32 hashHex(std::string_view hex);

    /// Hash the bytes into a 32-byte hash using keccak.
    Bytes32 hashBytesPtr(const void *bytes, size_t size);

    /// See `hashBytesPtr`
    Bytes32 hashBytes(std::span<const char> bytes);

    /// See `hashBytesPtr`
    Bytes32 hashBytes(std::span<const unsigned char> bytes);

    /// Get the function signature for Ethereum contract interaction via an ABI
    /// call
    std::string toEthFunctionSignature(std::string_view function);

    std::string trimAddress(const std::string& address);
}  // namespace ethyl::utils
}

