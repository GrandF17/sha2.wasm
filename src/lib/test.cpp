#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>

#include "hmac.class.cpp"
#include "sha2_224.class.cpp"
#include "sha2_256.class.cpp"
#include "sha2_384.class.cpp"
#include "sha2_512.class.cpp"


int main() {
    using clock = std::chrono::high_resolution_clock;

    size_t chunk = 1024ULL * 1024ULL;   // 1mb
    size_t total = chunk * 1024ULL;     // 1gb
    size_t message_len = chunk;
    uint8_t message[message_len]= {0};

    size_t out_len = 64;
    uint8_t out[out_len];

    size_t key_len = 72;
    uint8_t key[key_len]= {0x01, 0x02, 0x03};

    /** timestamp */
    auto start = clock::now();
    /** timestamp */

    HMAC<SHA2_512_HASH> hmac;

    hmac.init(key, key_len);
    for (size_t i = 0; i < total; i += chunk) {
        hmac.update(message, message_len);
    };
    hmac.digest(out);
    hmac.destroy();

    /** timestamp */
    auto end = clock::now();
    std::chrono::duration<double> diff = end - start;
    std::cout << "Time: " << diff.count() << " seconds\n";
    double speed = (double)total / (1024.0 * 1024.0) / diff.count();
    std::cout << "Speed: " << speed << " MB/s\n\n";
    /** timestamp */

    for (int i = 0; i < out_len; ++i) {
        std::cout
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(out[i])
            << " ";
    };

    std::cout << std::endl;
};