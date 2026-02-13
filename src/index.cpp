#include <iostream>
#include <iomanip>
#include <cstdint>

#include "./lib/core/sha224.hpp"

using namespace std;

int main() {
    SHA256::ctx c;

    size_t msg_len = 1024 * 1024 * 1024;
    uint8_t msg[msg_len];

    size_t out_len = 28;
    uint8_t out[out_len] = {0};

    SHA224::init(c);
    SHA224::update(c, msg, msg_len);
    SHA224::digest(c, out);

    for (int i = 0; i < sizeof(out); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(out[i]);
        std::cout << " ";
    };

    std::cout << std::endl;
    
    return 0;
};