#ifndef SHA512_CORE_HPP
#define SHA512_CORE_HPP


#include <cstdint>
#include <cstring>
#include <algorithm>

#include "../const.hpp"
#include "../utils.hpp"


namespace SHA512::Core {
  ////////////////////////////////////////////////////////////////
 ///////////////////////// PRIVATE BLOCK ////////////////////////
////////////////////////////////////////////////////////////////

    /** local Sigma0 (SHA-384/512) */
    inline uint64_t S0(const uint64_t x) {
        return (
            (x << 36 | x >> 28) ^   // right rotate (28)
            (x << 30 | x >> 34) ^   // right rotate (34)
            (x << 25 | x >> 39)     // right rotate (39)
        );
    };

    /** local Sigma1 (SHA-384/512) */
    inline uint64_t S1(const uint64_t x) {
        return (
            (x << 50 | x >> 14) ^  // right rotate (14)
            (x << 46 | x >> 18) ^  // right rotate (18)
            (x << 23 | x >> 41)    // right rotate (41)
        );
    };

    /** local sigma0 (SHA-384/512) */
    inline uint64_t s0(const uint64_t x) {
        return (
            (x << 63 | x >>  1) ^   // right rotate (1)
            (x << 56 | x >>  8) ^   // right rotate (8)
            (x >>  7          )     // right shift (7)
        );
    };

    /** local sigma1 (SHA-384/512) */
    inline uint64_t s1(const uint64_t x) {
        return (
            (x << 45 | x >> 19) ^   // right rotate (19)
            (x <<  3 | x >> 61) ^   // right rotate (61)
            (x >>  6          )     // right shift (6)
        );
    };

    /** 
     * local Majority (SHA-384/512) 
     * canonical: (x & y) ^ (x & z) ^ (y & z)
    */
    inline uint64_t maj(
        const uint64_t x,
        const uint64_t y,
        const uint64_t z
    ) {
        return (
            (x & y) | 
            (z & (x | y))
        );
    };

    /** local Choose (SHA-384/512) */
    inline uint64_t ch(
        const uint64_t x,
        const uint64_t y,
        const uint64_t z
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
    inline void core(uint64_t h[8], const uint64_t m[16]) {
        /** to modify copy of state */
        uint64_t A = h[0];
        uint64_t B = h[1];
        uint64_t C = h[2];
        uint64_t D = h[3];
        uint64_t E = h[4];
        uint64_t F = h[5];
        uint64_t G = h[6];
        uint64_t H = h[7];
        
        /** extend the first 16 words to 80 */
        uint64_t w[80];
        memcpy(w, m, 16 * sizeof(uint64_t));
        
        #pragma unroll
        for (size_t i = 16; i < 80; ++i) {
            w[i] = (
                s0(w[i - 15]) +
                s1(w[i - 2]) +
                w[i - 7] +
                w[i - 16]
            );
        };

        /** compress (80 rounds) */
        #pragma unroll
        for (size_t i = 0; i < 80; ++i) {
            uint64_t T1 = (H + S1(E) + ch(E, F, G) + SHA2::CONST::K512[i] + w[i]);
            uint64_t T2 = (S0(A) + maj(A, B, C));

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
};  // namespace SHA512::Core


#endif  // SHA512_CORE_HPP