#ifndef SHA256_H
#define SHA256_H

#include <cstring>


class SHA256 {
   public:
    /** bytes in word (Uint8 in Uint32) */
    size_t BIW;

    /** block size (Uint8) */
    size_t BSU8;

    /** block size (Uint32) */
    size_t BSU32;

    /** return block size (Uint8) */
    size_t RBSU8;

    /** return block size (Uint32) */
    size_t RBSU32;

    SHA256();
    ~SHA256();

    SHA256& init();
    void destroy();

    SHA256& update(const std::array<std::uint8_t>& data);
    std::array<std::uint8_t> digest();

   private:
    /** current state of SHA function */
    std::uint32_t state[this->BSU32];

    /** reusable buffer */
    std::uint8_t buff[this->BSU8];

    /** reusable core-buffer for extention */
    std::uint32_t buffCore[this->BSU8];

    /** buffer pointer */
    size_t p;

    /** total bytes hashed */
    size_t t;

    inline void core();

    static inline size_t x2buff(const array<uint8_t>& x, const int offset);

    static inline void cleanBuff();

    static inline void cleanState();

    static inline std::uint32_t S0(std::uint32_t x);

    static inline std::uint32_t S1(std::uint32_t x);

    static inline std::uint32_t s0(std::uint32_t x);

    static inline std::uint32_t s1(std::uint32_t x);

    static inline std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z);

    static inline std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z);
};

#endif // SHA256_H