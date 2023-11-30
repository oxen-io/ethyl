#include "ethyl/utils.hpp"

#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>

extern "C" {
#include "crypto/keccak.h"
}

std::string utils::decimalToHex(uint64_t decimal) {
    std::stringstream ss;
    ss << std::hex << decimal;
    return ss.str();
}

std::vector<unsigned char> utils::fromHexString(std::string hex_str) {
    std::vector<unsigned char> bytes;

    // Check for "0x" prefix and remove it
    if(hex_str.size() >= 2 && hex_str[0] == '0' && hex_str[1] == 'x') {
        hex_str = hex_str.substr(2);
    }

    for (unsigned int i = 0; i < hex_str.length(); i += 2) {
        std::string byteString = hex_str.substr(i, 2);
        //if (byteString[0] == 0) byteString[0] = '0';
        //if (byteString[1] == 0) byteString[1] = '0';
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

uint64_t utils::fromHexStringToUint64(std::string hex_str) {
    // Check for "0x" prefix and remove it
    if(hex_str.size() >= 2 && hex_str[0] == '0' && hex_str[1] == 'x') {
        hex_str = hex_str.substr(2);
    }

    uint64_t value = std::stoull(hex_str, nullptr, 16);
    return value;
}

std::array<unsigned char, 32> utils::fromHexString32Byte(std::string hex_str) {
    std::vector<unsigned char> bytesVec = fromHexString(hex_str);

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

std::string utils::padToNBytes(const std::string& input, size_t byte_count, utils::PaddingDirection direction) {
    std::string output = input;
    bool has0xPrefix = false;

    // Check if input starts with "0x" prefix
    if (output.substr(0, 2) == "0x") {
        has0xPrefix = true;
        output = output.substr(2);  // remove "0x" prefix for now
    }

    // Calculate padding size based on byteCount * 2 (since each byte is represented by 2 hex characters)
    size_t targetHexStringSize = byte_count * 2;
    size_t nextMultiple = (output.size() + targetHexStringSize - 1) / targetHexStringSize * targetHexStringSize;
    size_t paddingSize = nextMultiple - output.size();
    std::string padding(paddingSize, '0');

    if (direction == PaddingDirection::LEFT) {
        output = padding + output;
    } else {
        output += padding;
    }

    // If input started with "0x", add it back
    if (has0xPrefix) {
        output = "0x" + output;
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
