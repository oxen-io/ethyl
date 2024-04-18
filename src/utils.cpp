#include "ethyl/utils.hpp"

#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <cassert>

extern "C" {
#include "crypto/keccak.h"
}

std::string utils::decimalToHex(uint64_t decimal) {
    std::stringstream ss;
    ss << std::hex << decimal;
    return ss.str();
}

std::string_view utils::trimPrefix(std::string_view src, std::string_view prefix)
{
    std::string_view result = src;
    if (result.size() >= prefix.size()) {
        if (result.substr(0, prefix.size()) == prefix) {
            result = result.substr(prefix.size(), result.size() - prefix.size());
        }
    }
    return result;
}

std::string_view utils::trimLeadingZeros(std::string_view src)
{
    std::string_view result = src;
    while (result.size() && result[0] == '0') {
        result = result.substr(1, result.size() - 1);
    }
    return result;
}

struct HexToU8Result {
    bool    success;
    uint8_t u8;
};

static HexToU8Result hexToU8(char ch) {
    HexToU8Result result = {};
    result.success       = true;

    if (ch >= 'a' && ch <= 'f')
        result.u8 = static_cast<uint8_t>(ch - 'a' + 10);
    else if (ch >= 'A' && ch <= 'F')
        result.u8 = static_cast<uint8_t>(ch - 'A' + 10);
    else if (ch >= '0' && ch <= '9')
        result.u8 = static_cast<uint8_t>(ch - '0');
    else
        result.success = false;

    return result;
}

std::vector<unsigned char> utils::fromHexString(std::string_view hexStr) {
    hexStr = trimPrefix(hexStr, "0x");
    assert(hexStr.size() % 2 == 0);

    std::vector<unsigned char> result;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string_view byteString = hexStr.substr(i, 2);
        HexToU8Result    hi         = hexToU8(byteString[0]);
        HexToU8Result    lo         = hexToU8(byteString[1]);
        unsigned char    byte       = static_cast<unsigned char>(hi.u8 << 4 | lo.u8 << 0);
        result.push_back(byte);
    }
    return result;
}

uint64_t utils::fromHexStringToUint64(std::string_view hexStr) {
    std::string_view realHex = trimPrefix(hexStr, "0x");

    // NOTE: Trim leading '0's
    while (realHex.size() && realHex[0] == '0') {
        realHex = realHex.substr(1, realHex.size() - 1);
    }

    size_t maxHexSize = sizeof(uint64_t) * 2 /*hex chars per byte*/;
    assert(realHex.size() <= maxHexSize);

    size_t   size   = std::min(maxHexSize, realHex.size());
    uint64_t result = 0;
    for (size_t index = 0; index < size; index++) {
        char          ch        = realHex[index];
        HexToU8Result hexResult = hexToU8(ch);
        assert(hexResult.success);
        result = (result << 4) | hexResult.u8;
    }
    return result;
}

std::array<unsigned char, 32> utils::fromHexString32Byte(std::string_view hexStr) {
    std::vector<unsigned char> bytesVec = fromHexString(hexStr);

    if(bytesVec.size() != 32) {
        throw std::invalid_argument("Input string length should be 64 characters for 32 bytes");
    }

    std::array<unsigned char, 32> bytesArr;
    std::copy(bytesVec.begin(), bytesVec.end(), bytesArr.begin());

    return bytesArr;
}

std::array<unsigned char, 32> utils::hash(std::string in) {
    std::vector<unsigned char> bytes;

    // Check for "0x" prefix and if exists, convert the hex to bytes
    if(in.size() >= 2 && in[0] == '0' && in[1] == 'x') {
        bytes = fromHexString(in);
        in = std::string(bytes.begin(), bytes.end());
    }
    std::array<unsigned char, 32> hash;
    keccak(reinterpret_cast<const uint8_t*>(in.c_str()), in.size(), hash.data(), 32);
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

std::string utils::padToNBytes(const std::string& input, size_t byteCount, utils::PaddingDirection direction) {
    std::string output = input;
    bool has0xPrefix = false;

    // Check if input starts with "0x" prefix
    if (output.substr(0, 2) == "0x") {
        has0xPrefix = true;
        output = output.substr(2);  // remove "0x" prefix for now
    }

    // Calculate padding size based on byteCount * 2 (since each byte is represented by 2 hex characters)
    const size_t targetHexStringSize   = byteCount * 2;
    const size_t startingSize          = std::max(output.size(), static_cast<size_t>(1)); // Size is atleast 1 element such that we handle when output.size == 0
    const size_t startingSizeRoundedUp = startingSize + (targetHexStringSize - 1);
    const size_t nextMultiple          = /*floor*/ (startingSizeRoundedUp / targetHexStringSize) * targetHexStringSize;
    const size_t paddingSize           = nextMultiple - output.size();

    if (direction == PaddingDirection::LEFT) {
        output.insert(0, paddingSize, '0');
    } else {
        output.append(paddingSize, '0');
    }

    // If input started with "0x", add it back
    if (has0xPrefix) {
        output.insert(0, "0x");
    }

    return output;
}

std::string utils::padTo32Bytes(const std::string& input, PaddingDirection direction) {
    return padToNBytes(input, 32, direction);
}

std::string utils::padTo8Bytes(const std::string& input, PaddingDirection direction) {
    return padToNBytes(input, 8, direction);
}

std::vector<unsigned char> utils::intToBytes(uint64_t num) {
    if (num == 0) 
        return std::vector<unsigned char>{};

    std::stringstream stream;
    stream << std::hex << num;
    std::string hex = stream.str();
    if (hex.length() % 2) { hex = "0" + hex; }

    std::vector<unsigned char> result(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        result[i / 2] = byte;
    }

    return result;
}

std::vector<unsigned char> utils::removeLeadingZeros(std::vector<unsigned char> vec) {
    auto it = vec.begin();
    while(it != vec.end() && *it == 0) {
        ++it;
    }
    vec.erase(vec.begin(), it);
    return vec;
}

std::string utils::generateRandomString(size_t length) {
    srand(static_cast<unsigned int>(time(nullptr))); // Seed the random number generator
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const int64_t max_index = sizeof(charset) - 1;

    std::string randomString;

    for (size_t i = 0; i < length; ++i) {
        randomString += charset[static_cast<uint64_t>(rand() % max_index)];
    }

    return randomString;
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
