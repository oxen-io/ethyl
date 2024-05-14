#pragma once

#include <charconv>
#include <cstdint>
#include <span>
#include <string>
#include <array>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ios>

#include <oxenc/common.h>
#include <oxenc/hex.h>

namespace utils
{

    enum class PaddingDirection {
        LEFT,
        RIGHT
    };

    template <typename Container>
    std::string toHexString(const Container& bytes) {
        std::ostringstream oss;
        for(const auto byte : bytes) {
            oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(byte));
        }                                                                                                                     
        return oss.str();                                                                                                     
    }

    template <typename Container>
    std::string toHexStringBigEndian(const Container& bytes) {
        std::ostringstream oss;
        for(auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
            oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(*it));
        }
        return oss.str();
    }

    std::string      decimalToHex(uint64_t decimal);
    std::string_view trimPrefix(std::string_view src, std::string_view prefix);
    std::string_view trimLeadingZeros(std::string_view src);

    using oxenc::basic_char;
    template <basic_char Char = unsigned char>
    std::vector<Char> fromHexString(std::string_view hexStr) {
        hexStr = trimPrefix(hexStr, "0x");

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


    uint64_t fromHexStringToUint64(std::string_view hexStr);

    std::string padToNBytes(std::string_view hex_input, size_t bytes, PaddingDirection direction = PaddingDirection::LEFT);
    inline std::string padTo8Bytes(std::string_view hex_input, PaddingDirection direction = PaddingDirection::LEFT) {
        return padToNBytes(hex_input, 8, direction);
    }

    inline std::string padTo32Bytes(std::string_view hex_input, PaddingDirection direction = PaddingDirection::LEFT) {
        return padToNBytes(hex_input, 32, direction);
    }


    /// Parses an integer of some sort from a string, requiring that the entire string be consumed
    /// during parsing.  Return false if parsing failed, sets `value` and returns true if the entire
    /// string was consumed.
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

    std::array<unsigned char, 32> hash(std::string_view in);

    std::string getFunctionSignature(const std::string& function);

    std::vector<unsigned char> intToBytes(uint64_t num);

    std::vector<unsigned char> removeLeadingZeros(std::span<const unsigned char> vec);

    std::string trimAddress(const std::string& address);

// END
}
