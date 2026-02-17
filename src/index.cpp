#include <iostream>
#include <iomanip>

#include "./lib/core/sha224.class.cpp"
#include "./lib/core/hmac.hpp"

int main() {
    uint8_t key[] = {0x6b, 0x65, 0x79}; // "key"
    uint8_t msg[] = {0x61, 0x62, 0x63}; // "abc"

    HMAC<SHA224_HASH> hmac;

    hmac.init(key, sizeof(key));
    hmac.update(msg, sizeof(msg));

    uint8_t out[SHA224_HASH::digest_size];
    hmac.compute(out);

    for (int i = 0; i < SHA224_HASH::digest_size; ++i) {
        std::cout
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(out[i])
            << " ";
    };
    std::cout << std::endl;

    hmac.destroy();
};