#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/core/sha256.hpp"


struct SHA256TV {
    const char *message;
    const char *hash;
};

TEST(SHA256, RFC6234) {
    const SHA256TV tvs[] = {
        {
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        {
            "616263",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        },
        {
            "deadbeef",
            "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "693e5f0f347a5d70acbb7baaab9beb988301b3e9588e32c73d7dcdfb7b2c4604",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "deadbeef",
            "690b0da9ffddf8d13ddbe59242ffd6e3841c7947e9d647267d54614d3c5ec88e",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "512bf124b47b1c24f0aace1ad31d96c2b8b699d8153de63d49e181bc2ebcaaa1",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "e961fae4d0295a01244759fabd058f0b2a7cad688348266201b16ddf89db7d24",
        },
    };

    for (const auto &tv : tvs) {
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out(expected.size());

        SHA256::CTX ctx;
        SHA256::init(ctx);
        SHA256::update(ctx, message.data(), message.size());
        SHA256::digest(ctx, out.data());
        SHA256::destroy(ctx);

        EXPECT_EQ(out, expected);
    };
};