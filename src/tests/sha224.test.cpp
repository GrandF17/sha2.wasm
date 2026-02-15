#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/core/sha224.hpp"


struct SHA224TV {
    const char *message;
    const char *hash;
};

TEST(SHA224, RFC6234) {
    const SHA224TV tvs[] = {
        {
            "",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        },
        {
            "616263",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        },
        {
            "deadbeef",
            "55b9eee5f60cc362ddc07676f620372611e22272f60fdbec94f243f8",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "76e4742663e8086c7e954cbbea189f16779db7fed24b1abf17727b4a",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "deadbeef",
            "59cbcd28c6edd96d897ff297bf99dac8790398c2ef39fc5b9193ac7d",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cc7a8c5e9b7102930d9531d455e669198f400edabe01a50e9ecffa32",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "2d1111e812dff3ea136f33532bbc2e32c6a3d6d66da730293b69b47b",
        },
    };

    for (const auto &tv : tvs) {
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out(expected.size());

        SHA224::CTX ctx;
        SHA224::init(ctx);
        SHA224::update(ctx, message.data(), message.size());
        SHA224::digest(ctx, out.data());
        SHA224::destroy(ctx);

        EXPECT_EQ(out, expected);
    };
};