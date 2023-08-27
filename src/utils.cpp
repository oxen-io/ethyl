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

std::string utils::padTo32Bytes(const std::string& input, utils::PaddingDirection direction) {
    constexpr size_t targetSize = 64;
    std::string output = input;
    bool has0xPrefix = false;

    // Check if input starts with "0x" prefix
    if (output.substr(0, 2) == "0x") {
        has0xPrefix = true;
        output = output.substr(2);  // remove "0x" prefix for now
    }

    if(output.size() > targetSize) {
        throw std::runtime_error("Input size is greater than target size");
    }
    else if(output.size() < targetSize) {
        size_t paddingSize = targetSize - input.size();
        //std::string padding(paddingSize, 0);
        std::string padding(paddingSize, '0');

        if(direction == utils::PaddingDirection::LEFT) {
            output = padding + output;
        }
        else {
            output += padding;
        }
    }

    // If input started with "0x", add it back
    if (has0xPrefix) {
        output = "0x" + output;
    }

    return output;
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
