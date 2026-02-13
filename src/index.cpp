#include <iostream>
#include <iomanip>
#include <cstdint>
#include <chrono>
#include <vector>

#include "./lib/core/sha512.hpp"

using namespace std;

int main() {
    using clock = std::chrono::high_resolution_clock;

    SHA512::CTX c;

    size_t msg_len = 0; // 1 GB

    // НЕ на стеке!
    std::vector<uint8_t> msg(msg_len, 0);

    size_t out_len = 64;
    uint8_t out[64] = {0};

    auto start = clock::now();

    SHA512::init(c);

    size_t total = 1ull << 30;
    size_t chunk = 1ull << 20; // 1MB

    std::vector<uint8_t> buf(chunk, 0);

    for (size_t i = 0; i < total; i += chunk)
        SHA512::update(c, buf.data(), chunk);

    SHA512::digest(c, out);
    SHA512::destroy(c);

    auto end = clock::now();

    std::chrono::duration<double> diff = end - start;

    cout << "Time: " << diff.count() << " seconds\n";

    double speed = (double)msg_len / (1024.0 * 1024.0) / diff.count();
    cout << "Speed: " << speed << " MB/s\n\n";

    for (int i = 0; i < 64; ++i) {
        cout << hex << setw(2) << setfill('0')
             << static_cast<int>(out[i]) << " ";
    }

    cout << endl;
    return 0;
}
