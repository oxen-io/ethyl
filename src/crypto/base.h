#pragma once

#include <array>
#include <type_traits>

#include "common/format.h"
#include "common/formattable.h"
#include "common/hex.h"

namespace crypto {

/// constexpr null (all-0) value for various crypto types; use as `crypto::null<crypto::whatever>`.
template <
        typename T,
        typename = std::enable_if_t<
                std::is_standard_layout_v<T> && std::is_default_constructible_v<T>>>
constexpr T null{};

// Base type for fixed-byte quantities (points, scalars, signatures, hashes).  The bool controls
// whether the type should have ==, !=, std::hash, and to_hex_string.
template <size_t Bytes, bool MemcmpHashHex = false>
struct alignas(size_t) bytes {
    std::array<unsigned char, Bytes> data_;

    unsigned char* data() { return data_.data(); }
    const unsigned char* data() const { return data_.data(); }
    static constexpr size_t size() { return Bytes; }
    auto begin() { return data_.begin(); }
    auto begin() const { return data_.begin(); }
    auto cbegin() const { return data_.cbegin(); }
    auto end() { return data_.end(); }
    auto end() const { return data_.end(); }
    auto cend() const { return data_.cend(); }

    // Set the bytes to all 0's
    void zero() { data_.fill(0); }

    unsigned char& operator[](size_t i) { return data_[i]; }
    const unsigned char& operator[](size_t i) const { return data_[i]; }

    static constexpr bool compare_hash_hex = MemcmpHashHex;
};

template <typename T, typename = void>
constexpr bool has_compare_hash_hex = false;
template <typename T>
inline constexpr bool has_compare_hash_hex<T, std::enable_if_t<T::compare_hash_hex>> = true;

template <typename Left, typename Right, typename = void>
constexpr bool are_comparable_v = false;
template <typename L, typename R>
inline constexpr bool
        are_comparable_v<L, R, std::enable_if_t<std::is_same_v<L, R> && has_compare_hash_hex<L>>> =
                true;

template <typename L, typename R, std::enable_if_t<are_comparable_v<L, R>, int> = 0>
bool operator==(const L& left, const R& right) {
    return left.data_ == right.data_;
}
template <typename L, typename R, std::enable_if_t<are_comparable_v<L, R>, int> = 0>
bool operator!=(const L& left, const R& right) {
    return left.data_ != right.data_;
}
template <typename L, typename R, std::enable_if_t<are_comparable_v<L, R>, int> = 0>
bool operator<(const L& left, const R& right) {
    return left.data_ < right.data_;
}

template <typename T, typename = std::enable_if_t<has_compare_hash_hex<T>>>
std::string to_hex_string(const T& val) {
    return "<{}>"_format(tools::type_to_hex(val));
}

template <typename T>
struct raw_hasher {
    static_assert(T::compare_hash_hex);
    static_assert(std::is_standard_layout_v<T>);
    static_assert(sizeof(T) >= sizeof(size_t));
    static_assert(alignof(T) >= sizeof(size_t));

    size_t operator()(const T& val) const { return *reinterpret_cast<const size_t*>(val.data()); }
};
}  // namespace crypto

template <typename T>
inline constexpr bool
        formattable::via_to_hex_string<T, std::enable_if_t<crypto::has_compare_hash_hex<T>>> = true;
