#ifndef UTILS_HPP
#define UTILS_HPP


#include <cstdint>


namespace Utils {
    inline uint64_t to64LE(const uint8_t* p) {
        return
            ((uint64_t)p[0]      ) |
            ((uint64_t)p[1] <<  8) |
            ((uint64_t)p[2] << 16) |
            ((uint64_t)p[3] << 24) |
            ((uint64_t)p[4] << 32) |
            ((uint64_t)p[5] << 40) |
            ((uint64_t)p[6] << 48) |
            ((uint64_t)p[7] << 56);
    };

    inline uint32_t to32LE(const uint8_t* p) {
        return
            ((uint32_t)p[0]      ) |
            ((uint32_t)p[1] <<  8) |
            ((uint32_t)p[2] << 16) |
            ((uint32_t)p[3] << 24);
    };

    inline uint8_t from64LE(const uint64_t* w, size_t i) {
        size_t word  = i >> 3;
        size_t shift = (i & 7) << 3;
        return static_cast<uint8_t>((w[word] >> shift) & 0xFF);
    };

    inline uint8_t from32LE(const uint32_t* w, size_t i) {
        size_t word = i >> 2;
        size_t shift = (i & 3) << 3;
        return static_cast<uint8_t>((w[word] >> shift) & 0xFF);
    };
};  // namespace Utils


#endif  // UTILS_HPP