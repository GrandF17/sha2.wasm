// #include <iostream>
// #include <iomanip>
// #include <cstdint>
// #include <chrono>
// #include <vector>

// #include "./lib/core/sha224.hpp"
// #include "./lib/core/sha256.hpp"
// #include "./lib/core/sha384.hpp"
// #include "./lib/core/sha512.hpp"

// using namespace std;

// int main() {
//     using clock = std::chrono::high_resolution_clock;

//     SHA512::CTX c;

//     size_t total = 1024ull * 1024ull * 1024ull; // 1 GB
//     size_t chunk = 1ull << 20;  // 1MB

//     auto start = clock::now();

//     SHA384::init(c);

//     std::vector<uint8_t> buf(chunk, 0);

//     size_t out_len = 48;
//     std::vector<uint8_t> out(out_len, 0);

//     for (size_t i = 0; i < total; i += chunk) {
//         SHA384::update(c, buf.data(), chunk);
//     };

//     SHA384::digest(c, out.data());
//     SHA384::destroy(c);

//     auto end = clock::now();

//     std::chrono::duration<double> diff = end - start;

//     cout << "Time: " << diff.count() << " seconds\n";

//     double speed = (double)total / (1024.0 * 1024.0) / diff.count();
//     cout << "Speed: " << speed << " MB/s\n\n";

//     for (int i = 0; i < out_len; ++i) {
//         cout
//             << hex
//             << setw(2)
//             << setfill('0')
//             << static_cast<int>(out[i])
//             << " ";
//     };
//     cout << endl;
    
//     return 0;
// };

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <chrono>
#include <vector>

#include "./lib/core/sha224.hpp"
#include "./lib/core/sha256.hpp"
#include "./lib/core/sha384.hpp"
#include "./lib/core/sha512.hpp"

using namespace std;

int main() {
    SHA256::CTX c;

    size_t msg_len = 4;
    uint8_t msg[msg_len] = {
        0x63, 0x62, 0x61, 0x60
    };

    size_t out_len = 32;
    uint8_t out[out_len] = {0};

    SHA256::init(c);
    SHA256::update(c, msg, msg_len);
    SHA256::digest(c, out);
    SHA256::destroy(c);

    for (int i = 0; i < out_len; ++i) {
        cout
            << hex
            << setw(2)
            << setfill('0')
            << static_cast<int>(out[i])
            << " ";
    };
    cout << endl;
    
    return 0;
};