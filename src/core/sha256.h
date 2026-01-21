#ifndef SHA256_H
#define SHA256_H

#include <cstring>
#include <iostream>
#include <vector>

using namespace std;

class SHA256 {
   public:

    /** 
     * constructor
     */
    SHA256();

    this init(const vector<uint8_t>& key);

    void destroy();

    this update(const vector<uint8_t>& message);

    this digest();

   private:

    static inline void core();

    static inline int x2buff(const vector<uint8_t>& x, const int offset);

    static inline void cleanBuff();

    static inline void cleanState();

    static inline uint64_t S0(uint64_t x);

    static inline uint64_t S1(uint64_t x);

    static inline uint64_t s0(uint64_t x);

    static inline uint64_t s1(uint64_t x);

    static inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z);

    static inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z);
};

#endif