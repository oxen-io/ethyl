#include "ethyl/utils.hpp"

#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <cstdlib>
#include <ctime>
#include <iterator>
#include <string>

extern "C" {
#include "crypto/keccak.h"
}

std::string utils::decimalToHex(uint64_t decimal) {
    char buf[20];
    auto [end, ec] = std::to_chars(std::begin(buf), std::end(buf), decimal, 16);
    return {buf, ec == std::errc{} ? static_cast<size_t>(end - buf) : 0};
}

std::string_view utils::trimPrefix(std::string_view src, std::string_view prefix) {
    if (src.starts_with(prefix))
        return src.substr(prefix.size());
    return src;
}

std::string_view utils::trimLeadingZeros(std::string_view src) {
    if (auto p = src.find_first_not_of('0'); p != src.npos)
        return src.substr(p);
    return src;
}

uint64_t utils::fromHexStringToUint64(std::string_view hexStr) {
    uint64_t val;
    if (parseInt(trimPrefix(hexStr, "0x"), val, 16))
        return val;

    throw std::invalid_argument{"failed to parse integer from hex input"};
}

template std::vector<char> utils::fromHexString<char>(std::string_view);
template std::vector<unsigned char> utils::fromHexString<unsigned char>(std::string_view);
template std::array<char, 32> utils::fromHexString32Byte<char>(std::string_view);
template std::array<unsigned char, 32> utils::fromHexString32Byte<unsigned char>(std::string_view);

std::array<unsigned char, 32> utils::hash(std::string_view in) {
    std::vector<char> bytes;

    // Check for "0x" prefix and if exists, convert the hex to bytes
    if (in.starts_with("0x")) {
        bytes = fromHexString<char>(in);
        in = {bytes.data(), bytes.size()};
    }
    std::array<unsigned char, 32> hash;
    keccak(reinterpret_cast<const uint8_t*>(in.data()), in.size(), hash.data(), 32);
    return hash;
}

// Function to get the function signature for Ethereum contract interaction
std::string utils::getFunctionSignature(const std::string& function) {
    std::array<unsigned char, 32> hash = utils::hash(function);

    // Convert the hash to hex string
    std::string hashHex = toHexString(hash);

    // Return the first 8 characters of the hex string (4 bytes) plus 0x prefix
    return "0x" + hashHex.substr(0, 8);
}

std::string utils::padToNBytes(
        std::string_view hex_input, size_t bytes, utils::PaddingDirection direction) {
    bool has_0x_prefix = hex_input.starts_with("0x");
    size_t target_size = 2 * bytes + 2 * has_0x_prefix;
    if (hex_input.size() >= target_size)
        return std::string{hex_input};

    std::string out;
    out.reserve(target_size);

    if (direction == PaddingDirection::RIGHT) {
        out += hex_input;
        out.resize(target_size, '0');
    } else {
        if (has_0x_prefix) {
            out += "0x";
            hex_input.remove_prefix(2);
        }
        out.resize(target_size - hex_input.size(), '0');
        out += hex_input;
    }
    return out;
}

std::vector<unsigned char> utils::intToBytes(uint64_t num) {
    std::array<unsigned char, 8> buf;
    oxenc::write_host_as_big(num, buf.data());
    return removeLeadingZeros(buf);
}

std::vector<unsigned char> utils::removeLeadingZeros(std::span<const unsigned char> vec) {
    auto it = vec.begin();
    while (it != vec.end() && *it == 0) {
        ++it;
    }
    return {it, vec.end()};
}

std::string utils::trimAddress(const std::string& address) {
    if (address.length() <= 42) {
        // Address is already 20 bytes or shorter, no need to trim
        return address;
    }

    // Check if the address starts with "0x" or "0X"
    if (address.substr(0, 2) != "0x" && address.substr(0, 2) != "0X") {
        return address;
    }

    // Find the first non-zero character after "0x"
    size_t firstNonZero = address.find_first_not_of('0', 2);
    if (firstNonZero == std::string::npos) {
        // Address only contains zeros, return "0x" followed by 20 bytes of zero
        return "0x" + std::string(40, '0');
    }

    // Trim and return the address
    return "0x" + address.substr(firstNonZero, 40);
}
