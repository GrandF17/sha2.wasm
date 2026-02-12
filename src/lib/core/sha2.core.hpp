#ifndef SHA2_CORE_HPP
#define SHA2_CORE_HPP


#include <cstdint>
#include <cstring>
#include <algorithm>

#include "../const.hpp"
#include "../utils.hpp"


namespace SHA2::Core {
  ////////////////////////////////////////////////////////////////
 ///////////////////////// PRIVATE BLOCK ////////////////////////
////////////////////////////////////////////////////////////////

    /** local Sigma0 (SHA-224/256) */
    inline uint32_t S0(const uint32_t x) {
        return (
            (x << 30 | x >>  2) ^   // right rotate (2)
            (x << 19 | x >> 13) ^   // right rotate (13)
            (x << 10 | x >> 22)     // right rotate (22)
        );
    };

    /** local Sigma1 (SHA-224/256) */
    inline uint32_t S1(const uint32_t x) {
        return (
            (x << 26 | x >>  6) ^  // right rotate (6)
            (x << 21 | x >> 11) ^  // right rotate (11)
            (x <<  7 | x >> 25)    // right rotate (25)
        );
    };

    /** local sigma0 (SHA-224/256) */
    inline uint32_t s0(const uint32_t x) {
        return (
            (x << 25 | x >>  7) ^   // right rotate (7)
            (x << 14 | x >> 18) ^   // right rotate (18)
            (x >>  3          )     // right shift (3)
        );
    };

    /** local sigma1 (SHA-224/256) */
    inline uint32_t s1(const uint32_t x) {
        return (
            (x << 15 | x >> 17) ^   // right rotate (17)
            (x << 13 | x >> 19) ^   // right rotate (19)
            (x >> 10          )     // right shift (10)
        );
    };

    /** 
     * local Majority (SHA-224/256) 
     * canonical: (x & y) ^ (x & z) ^ (y & z)
    */
    inline uint32_t maj(
        const uint32_t x,
        const uint32_t y,
        const uint32_t z
    ) {
        return (
            (x & y) | 
            (z & (x | y))
        );
    };

    /** local Choose (SHA-224/256) */
    inline uint32_t ch(
        const uint32_t x,
        const uint32_t y,
        const uint32_t z
    ) {
        return (
            ( x & y) ^ 
            (~x & z)
        );
    };

    /** 
     * compression function for blake2b
     * @param h - current hash-functioin state
     * @param m - message block
     * @param t0 - lo counter
     * @param t1 - hi counter
     * @param last - last block of message 
     */
    inline void core32(
        uint64_t h[8],
        const uint64_t m[16]
    ) {
        
    };
};  // namespace SHA2::Core


#endif  // SHA2_CORE_HPP