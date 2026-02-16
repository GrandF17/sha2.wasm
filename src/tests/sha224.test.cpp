#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/core/sha224.hpp"


struct SHA224TV {
    const char *message;
    const char *hash;
};

TEST(SHA224, RFC6234) {
    const SHA224TV tvs[] = {
        /** empty string */
        {
            "",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        },
        /** ASCII "abc" */
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
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
        {
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" */
        {
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." */
        {
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
        },
        /** boundary: single zero byte */
        {
            "00",
            "fff9292b4201617bdc4d3053fce02734166a683d7d858a7f5f59b073",
        },
        /** boundary: 56 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
            "7145705f5c74f844d2e4e109aa862f4e0735aa0d32f699673d888797",
        },
        /** boundary: 63 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee",
            "2c5fd88d27a9f7f3f33f9cdcd72d6cd5c9f06b78d4435ef746d16967",
        },
        /** boundary: 64 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "d718ac99b7e5db7a2cfae482ccfec85919352d2ab399d0e4e8b8def6",
        },
    };

    for (const auto &tv : tvs) {
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out_single(expected.size());
        std::vector<uint8_t> out_split(expected.size());

        /** single-shot */
        {
            SHA224::CTX ctx;
            SHA224::init(ctx);
            SHA224::update(ctx, message.data(), message.size());
            SHA224::digest(ctx, out_single.data());
            SHA224::destroy(ctx);
        }

        /** two-shots */
        {
            SHA224::CTX ctx;
            SHA224::init(ctx);

            size_t half = message.size() / 2;

            SHA224::update(ctx, message.data(), half);
            SHA224::update(ctx, message.data() + half, message.size() - half);

            SHA224::digest(ctx, out_split.data());
            SHA224::destroy(ctx);
        }

        EXPECT_EQ(out_single, expected);
        EXPECT_EQ(out_split, expected);
        EXPECT_EQ(out_single, out_split);
    };
};