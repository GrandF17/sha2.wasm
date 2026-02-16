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
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
        {
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" */
        {
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." */
        {
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        },
        /** boundary: single zero byte */
        {
            "00",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        },
        /** boundary: 56 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
            "65ea547b30e3e8e7d6e58b60212a962c38fadef45e0e68fa7d51ed6d91faa1aa",
        },
        /** boundary: 63 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee",
            "a08d415add2994f1dbced478986888eb54c72097af88ae43fd973b49260aa51e",
        },
        /** boundary: 64 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "18546d1e498dd4ba544982e3bbd096904dd780a5d7a483b1bfc9216060072def",
        },
    };

    for (const auto &tv : tvs) {
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out_single(expected.size());
        std::vector<uint8_t> out_split(expected.size());

        /** single-shot */
        {
            SHA256::CTX ctx;
            SHA256::init(ctx);
            SHA256::update(ctx, message.data(), message.size());
            SHA256::digest(ctx, out_single.data());
            SHA256::destroy(ctx);
        }

        /** two-shots */
        {
            SHA256::CTX ctx;
            SHA256::init(ctx);

            size_t half = message.size() / 2;

            SHA256::update(ctx, message.data(), half);
            SHA256::update(ctx, message.data() + half, message.size() - half);

            SHA256::digest(ctx, out_split.data());
            SHA256::destroy(ctx);
        }

        EXPECT_EQ(out_single, expected);
        EXPECT_EQ(out_split, expected);
        EXPECT_EQ(out_single, out_split);
    };
};