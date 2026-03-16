#ifndef UTILS_HPP
#define UTILS_HPP


namespace Utils {
    namespace Crypto {
        /** portable secure clean function */
        inline void secure_zero(void *ptr, size_t len) {
            volatile unsigned char *p =
                reinterpret_cast<volatile unsigned char*>(ptr);

            while (len--) {
                *p++ = 0;
            };

            #if defined(__GNUC__) || defined(__clang__)
                __asm__ __volatile__("" : : "r"(ptr) : "memory");
            #endif
        };

        /** 
         * constant time comparison of 2 byte arrays
         * @returns true/false
         */
        inline int secure_cmp(const uint8_t *a, const uint8_t *b, size_t len) {
            uint8_t diff = 0;

            for (size_t i = 0; i < len; ++i) {
                diff |= a[i] ^ b[i];
            };

            return (int)(1 & ((diff - 1) >> 8));
        };
    };

    /** Big-Endian parser/formatter */
    namespace BE {
        inline uint64_t to64(const uint8_t *p) {
            return (
                ((uint64_t)p[7]      ) |
                ((uint64_t)p[6] <<  8) |
                ((uint64_t)p[5] << 16) |
                ((uint64_t)p[4] << 24) |
                ((uint64_t)p[3] << 32) |
                ((uint64_t)p[2] << 40) |
                ((uint64_t)p[1] << 48) |
                ((uint64_t)p[0] << 56)
            );
        };
        
        inline uint32_t to32(const uint8_t *p) {
            return (
                ((uint32_t)p[3]      ) |
                ((uint32_t)p[2] <<  8) |
                ((uint32_t)p[1] << 16) |
                ((uint32_t)p[0] << 24)
            );
        };
        
        inline void store64(uint8_t *p, uint64_t v) {
            p[0] = (uint8_t)(v >> 56);
            p[1] = (uint8_t)(v >> 48);
            p[2] = (uint8_t)(v >> 40);
            p[3] = (uint8_t)(v >> 32);
            p[4] = (uint8_t)(v >> 24);
            p[5] = (uint8_t)(v >> 16);
            p[6] = (uint8_t)(v >>  8);
            p[7] = (uint8_t)(v      );
        };

        inline void store32(uint8_t *p, uint32_t v) {
            p[0] = (uint8_t)(v >> 24);
            p[1] = (uint8_t)(v >> 16);
            p[2] = (uint8_t)(v >>  8);
            p[3] = (uint8_t)(v      );
        };
        
        inline uint8_t from64(const uint64_t *w, size_t i) {
            size_t word  = i >> 3;
            size_t shift = (7 - (i & 7)) << 3;
            return static_cast<uint8_t>((w[word] >> shift) & 0xFF);
        };
        
        inline uint8_t from32(const uint32_t *w, size_t i) {
            size_t word  = i >> 2;
            size_t shift = (3 - (i & 3)) << 3;
            return static_cast<uint8_t>((w[word] >> shift) & 0xFF);
        };
    };

    /** Little-Endian parser/formatter */
    namespace LE {
        inline uint64_t to64(const uint8_t *p) {
            return (
                ((uint64_t)p[0]      ) |
                ((uint64_t)p[1] <<  8) |
                ((uint64_t)p[2] << 16) |
                ((uint64_t)p[3] << 24) |
                ((uint64_t)p[4] << 32) |
                ((uint64_t)p[5] << 40) |
                ((uint64_t)p[6] << 48) |
                ((uint64_t)p[7] << 56)
            );
        };

        inline uint32_t to32(const uint8_t *p) {
            return (
                ((uint32_t)p[0]      ) |
                ((uint32_t)p[1] <<  8) |
                ((uint32_t)p[2] << 16) |
                ((uint32_t)p[3] << 24)
            );
        };

        inline void store64(uint8_t *p, uint64_t v) {
            p[0] = (uint8_t)(v      );
            p[1] = (uint8_t)(v >>  8);
            p[2] = (uint8_t)(v >> 16);
            p[3] = (uint8_t)(v >> 24);
            p[4] = (uint8_t)(v >> 32);
            p[5] = (uint8_t)(v >> 40);
            p[6] = (uint8_t)(v >> 48);
            p[7] = (uint8_t)(v >> 56);
        };

        inline void store32(uint8_t *p, uint32_t v) {
            p[0] = (uint8_t)(v      );
            p[1] = (uint8_t)(v >>  8);
            p[2] = (uint8_t)(v >> 16);
            p[3] = (uint8_t)(v >> 24);
        };
        
        inline uint8_t from64(const uint64_t *w, size_t i) {
            size_t word  = i >> 3;
            size_t shift = (i & 7) << 3;
            return static_cast<uint8_t>((w[word] >> shift) & 0xFF);
        };

        inline uint8_t from32(const uint32_t *w, size_t i) {
            size_t word = i >> 2;
            size_t shift = (i & 3) << 3;
            return static_cast<uint8_t>((w[word] >> shift) & 0xFF);
        };
    };
};  // namespace Utils


#endif  // UTILS_HPP