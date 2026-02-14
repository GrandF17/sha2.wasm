#include <vector>
#include <string>
#include <cstdint>


static std::vector<uint8_t> hex(const std::string &s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);

    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back(
            static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16))
        );
    };
    return out;
};