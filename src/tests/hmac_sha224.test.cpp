#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/hmac.class.cpp"
#include "../lib/sha224.class.cpp"


struct TV {
    const char *key;
    const char *message;
    const char *hash;
};

TEST(HMAC, SHA224) {
    const TV tvs[] = {
        /** empty string (short key) */
        {
            "abcdef",
            "",
            "136ee74ad4fbbef654005537120690dd73eee94d06c27b0690f775da",
        },
        /** ASCII "abc" (short key) */
        {
            "abcdef",
            "616263",
            "b6887964db93ce8927c7ac0bda7fe8dfe1f67c73ca9c130578d1caf9",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (short key) */
        {
            "abcdef",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "b3c2b20875220b87729dc5bd82527545e32ed85461ac826b2412d009",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (short key) */
        {
            "abcdef",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "7b8cbd3f2a7749a83799955db7a526d8f2406c3d523ce0e1af62a763",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (short key) */
        {
            "abcdef",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "038ed5cea1e5356a7baf339f4bf8021734adebf96214c6ba9613a215",
        },
        /** empty string (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "",
            "53ff5fa4b13e57b6f220115b9f40e7964d6f37f57f393d2225e013ab",
        },
        /** ASCII "abc" (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "616263",
            "5b46084d3c6166b98bc36bccbfbe068db0a256d6c0afbb3b239e9341",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "8f5d0123d8af4a1b01b88a61c34a95b9bcc4d3c6a819df2af35277bb",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "6eb643a12e20f9c5ee0321e94df8b2862c354421b861c40580dad97e",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (long key) */
        {
            "7654d0c0b9994aa6b4551015a66b55d79ac5903a6d83b080aa0d269aa4b3219004d7e0aaa23b515f782919bb9797bdac4e8b4a87d5cfd5dcb54fc4b4d01a7a19"
            "c8",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "9845e7e3f6f91b5a864f24c63aadf351abe6c516945389ccd36a6521",
        },
    };

    for (const auto &tv : tvs) {
        auto key      = hex(tv.key);
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out_single(expected.size());
        std::vector<uint8_t> out_split(expected.size());
        HMAC<SHA224_HASH> hmac;

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