#include "utils.hpp"
#include <cstdlib>
#include <ctime>
#include <sstream>

extern "C" {
    #include "crypto/keccak.h"
}

namespace utils {

    std::string decimalToHex(uint64_t decimal) {
        std::stringstream ss;
        ss << std::hex << decimal;
        return ss.str();
    }

    std::vector<unsigned char> fromHexString(const std::string& hex_str) {
        size_t offset = 0;
        std::string cleaned_hex;

        if (hex_str.size() >= 2 && hex_str.substr(0, 2) == "0x") {
            offset = 2;
        }

        cleaned_hex = hex_str.substr(offset);
        if (cleaned_hex.length() % 2 != 0) {
            throw std::invalid_argument("Hex string must have an even length");
        }

        std::vector<unsigned char> bytes;
        bytes.reserve(cleaned_hex.length() / 2);

        for (size_t i = 0; i < cleaned_hex.length(); i += 2) {
            unsigned char byte = static_cast<unsigned char>(std::stoul(cleaned_hex.substr(i, 2), nullptr, 16));
            bytes.push_back(byte);
        }

        return bytes;
    }

    uint64_t fromHexStringToUint64(std::string hex_str) {
        if(hex_str.size() >= 2 && hex_str[0] == '0' && hex_str[1] == 'x') {
            hex_str = hex_str.substr(2);
        }

        return std::stoull(hex_str, nullptr, 16);
    }

    std::array<unsigned char, 32> fromHexString32Byte(std::string hex_str) {
        std::vector<unsigned char> bytesVec = fromHexString(hex_str);

        if(bytesVec.size() != 32) {
            throw std::invalid_argument("Input string length should be 64 characters for 32 bytes");
        }

        std::array<unsigned char, 32> bytesArr;
        std::copy(bytesVec.begin(), bytesVec.end(), bytesArr.begin());

        return bytesArr;
    }

    std::array<unsigned char, 32> hash(std::string in) {
        std::vector<unsigned char> bytes;

        if(in.size() >= 2 && in[0] == '0' && in[1] == 'x') {
            bytes = fromHexString(in);
            in = std::string(bytes.begin(), bytes.end());
        }

        std::array<unsigned char, 32> hash;
        keccak(reinterpret_cast<const uint8_t*>(in.c_str()), in.size(), hash.data(), 32);
        return hash;
    }

    std::string getFunctionSignature(const std::string& function) {
        std::array<unsigned char, 32> hash = utils::hash(function);
        std::string hashHex = toHexString(hash);
        return "0x" + hashHex.substr(0, 8);
    }

    std::string padToNBytes(const std::string& input, size_t byte_count, PaddingDirection direction) {
        std::string output = input;
        bool has0xPrefix = false;

        if (output.substr(0, 2) == "0x") {
            has0xPrefix = true;
            output = output.substr(2);
        }

        size_t targetHexStringSize = byte_count * 2;
        size_t nextMultiple = (output.size() + targetHexStringSize - 1) / targetHexStringSize * targetHexStringSize;
        size_t paddingSize = nextMultiple - output.size();
        std::string padding(paddingSize, '0');

        if (direction == PaddingDirection::LEFT) {
            output = padding + output;
        } else {
            output += padding;
        }

        if (has0xPrefix) {
            output = "0x" + output;
        }

        return output;
    }

    std::vector<unsigned char> intToBytes(uint64_t num) {
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

    std::vector<unsigned char> removeLeadingZeros(std::vector<unsigned char> vec) {
        auto it = vec.begin();
        while(it != vec.end() && *it == 0) {
            ++it;
        }
        vec.erase(vec.begin(), it);
        return vec;
    }

    std::string generateRandomString(size_t length) {
        srand(static_cast<unsigned int>(time(nullptr)));  // Seed the random number generator
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        const int64_t max_index = sizeof(charset) - 1;

        std::string randomString;
        for (size_t i = 0; i < length; ++i) {
            randomString += charset[static_cast<uint64_t>(rand() % max_index)];
        }

        return randomString;
    }

    std::string trimAddress(const std::string& address) {
        if (address.length() <= 42) {
            return address;
        }

        if (address.substr(0, 2) != "0x" && address.substr(0, 2) != "0X") {
            return address;
        }

        size_t firstNonZero = address.find_first_not_of('0', 2);
        if (firstNonZero == std::string::npos) {
            return "0x" + std::string(40, '0');
        }

        return "0x" + address.substr(firstNonZero, 40);
    }

} 
