#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/hmac.class.cpp"
#include "../lib/sha256.class.cpp"


struct TV {
    const char *key;
    const char *message;
    const char *hash;
};

TEST(HMAC, SHA256) {
    const TV tvs[] = {
        /** empty string (short key) */
        {
            "abcdef",
            "",
            "0f6c81293c0aa9cf39761ed2dff1335114ed9c0b8579d3e7b3b2f65c77452ab3",
        },
        /** ASCII "abc" (short key) */
        {
            "abcdef",
            "616263",
            "7fb6acfd763f1673c0fdcb26c723ce23bc02b5c6655dba6fdbc49a320e3db250",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (short key) */
        {
            "abcdef",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "2dcf75bc0c94fb545d1eb499aed53e268c5f54d732f7ecefaf3a2ee1439446f8",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (short key) */
        {
            "abcdef",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "2ba2ae800571a68c95aa7a62e35256014cc663fee61689eed0f234af32be26a8",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (short key) */
        {
            "abcdef",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "7d1478e2afa52b0e7b13fe16f5c68f14fb61ea6a781ad77972f949fca9d66e48",
        },
        /** empty string (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "",
            "5eba3f5c4577c0b0631b3db1667cb4b3d10404a94b9a514b6934e1b8ca5b4897",
        },
        /** ASCII "abc" (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "616263",
            "98f54728f253bdffa21288dfc8890d7b8597816edca78fc8435c334325b129b1",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "84ff1a4bbbf9d8f34b4bc8e2d269645234acbc4372b6e751b7cf4c113133dc3b",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "3851fb79b49317ee8cadf70431a31d6283b70abefd5a47b2010b5933789a535d",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "0064204c669a232e7dbe1c2aefd6e999886686084b1c9166c989fea62cb424eb",
        },
    };

    for (const auto &tv : tvs) {
        auto key      = hex(tv.key);
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out_single(expected.size());
        std::vector<uint8_t> out_split(expected.size());
        HMAC<SHA256_HASH> hmac;

        /** single-shot */
        {
            hmac.init(key.data(), key.size());
            hmac.update(message.data(), message.size());
            hmac.digest(out_single.data());
            hmac.destroy();
        }

        /** two-shots */
        {
            hmac.init(key.data(), key.size());

            size_t half = message.size() / 2;

            hmac.update(message.data(), half);
            hmac.update(message.data() + half, message.size() - half);

            hmac.digest(out_split.data());
            hmac.destroy();
        }

        EXPECT_EQ(out_single, expected);
        EXPECT_EQ(out_split, expected);
        EXPECT_EQ(out_single, out_split);
    };
};