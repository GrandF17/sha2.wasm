#ifndef SHA256_CORE_HPP
#define SHA256_CORE_HPP


#include <cstdint>
#include <cstring>
#include <algorithm>

#include "../const.hpp"
#include "../utils.hpp"


namespace SHA256::Core {
  ////////////////////////////////////////////////////////////////
 ///////////////////////// PRIVATE BLOCK ////////////////////////
////////////////////////////////////////////////////////////////

    /** local Sigma0 (SHA-224/256) */
    inline uint32_t S0(uint32_t x) {
        return (
            (x << 30 | x >>  2) ^   // right rotate (2)
            (x << 19 | x >> 13) ^   // right rotate (13)
            (x << 10 | x >> 22)     // right rotate (22)
        );
    };

    /** local Sigma1 (SHA-224/256) */
    inline uint32_t S1(uint32_t x) {
        return (
            (x << 26 | x >>  6) ^  // right rotate (6)
            (x << 21 | x >> 11) ^  // right rotate (11)
            (x <<  7 | x >> 25)    // right rotate (25)
        );
    };

    /** local sigma0 (SHA-224/256) */
    inline uint32_t s0(uint32_t x) {
        return (
            (x << 25 | x >>  7) ^   // right rotate (7)
            (x << 14 | x >> 18) ^   // right rotate (18)
            (x >>  3          )     // right shift (3)
        );
    };

    /** local sigma1 (SHA-224/256) */
    inline uint32_t s1(uint32_t x) {
        return (
            (x << 15 | x >> 17) ^   // right rotate (17)
            (x << 13 | x >> 19) ^   // right rotate (19)
            (x >> 10          )     // right shift (10)
        );
    };

    /** local Majority (SHA-224/256) */
    inline uint32_t maj(
        uint32_t x,
        uint32_t y,
        uint32_t z
    ) {
        return (
            (x & y) ^
            (x & z) ^
            (y & z)
        );
    };

    /** local Choose (SHA-224/256) */
    inline uint32_t ch(
        uint32_t x,
        uint32_t y,
        uint32_t z
    ) {
        return (
            ( x & y) ^ 
            (~x & z)
        );
    };

  ////////////////////////////////////////////////////////////////
 ///////////////////////// PUBLIC BLOCK /////////////////////////
////////////////////////////////////////////////////////////////

    /** 
     * compression function for sha2
     * @param h - current hash-functioin state
     * @param m - message block in Big-endian fromat
     */
    inline void core(uint32_t *__restrict h, const uint32_t *__restrict m) {
        /** to modify copy of state */
        uint32_t A = h[0];
        uint32_t B = h[1];
        uint32_t C = h[2];
        uint32_t D = h[3];
        uint32_t E = h[4];
        uint32_t F = h[5];
        uint32_t G = h[6];
        uint32_t H = h[7];
        
        /** extend the first 16 words to 64 */
        uint64_t w[64] = {0};
        memcpy(w, m, 16 * sizeof(uint32_t));

        /** compress (64 rounds) */
        for (size_t i = 0; i < 64; ++i) {
            /** 1) extend */
            if(i >= 16) {
                w[i] = (
                    s0(w[i - 15]) +
                    s1(w[i - 2]) +
                    w[i - 7] +
                    w[i - 16]
                );
            };

            /** 2) compress */
            uint32_t T1 = (H + S1(E) + ch(E, F, G) + SHA2::CONST::K256[i] + w[i]);
            uint32_t T2 = (S0(A) + maj(A, B, C));

            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
        };

        /** add result to state */
        h[0] += A;
        h[1] += B;
        h[2] += C;
        h[3] += D;
        h[4] += E;
        h[5] += F;
        h[6] += G;
        h[7] += H;
    };
};  // namespace SHA256::Core


#endif  // SHA256_CORE_HPP