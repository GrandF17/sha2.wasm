#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/hmac.class.cpp"
#include "../lib/sha512.class.cpp"


struct TV {
    const char *key;
    const char *message;
    const char *hash;
};

TEST(HMAC, SHA512) {
    const TV tvs[] = {
        /** empty string (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "",
            "eeb2e7dc1ea7c75966552a7f45c9f30e3fb9a7ea1362ba6d7324dd7def461f88b2b5e433cd7ca25a08554605b0b020c3a865434babfc140de5d55c8a94c7fdc6",
        },
        /** ASCII "abc" (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "616263",
            "f5b41f81b56d9cef4bfffbdd659470ca9de7348a23dac136790b028986d13e7d74dc59759faea253d5342abd56cf6f5859145ad54bca62e0c45245b7e4fa5c53",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "e78f92e31d7410dd16ec830b477fe703b79925811758f0d3a11f3e4f48da0c2687a797eb2e3d7e20026936a87e6903f9d8c93ef3e8fecf2cb2a42a720f301821",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "7b384fac5381f2bed304e936e149b282db3f01578d4e9b8aea2402ee9e0ce6c72255493e3a811dec59f1bbe46e2386eaa3cd6040d46aafb6b892c0fa3b90b28b",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "a7e721fb8a4d661d3060ba87b3ea89fb5ebcde938ea67ea1031d10d0b7ce2beff24b6f4a2507b5a308cd04ba6f2bda9eec689c86d048ffc2b5c7383d52c8e2e1",
        },
        /** empty string (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "",
            "e0a233c44cdf02b23aa175ac7ae7a6f4e0aca75ec716e19c911d76332e84db9a1d1fa4b8282b644743301cc404aa8de21862ff431c15cce9db6975b418bcd811",
        },
        /** ASCII "abc" (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "616263",
            "9c0d36c6617b89aeab6a9ba23732a1e28ff0e0a8808042fd2db6862534092e7e1f7be04a2364b7b751eff60fd3e0f3f536539e9f17d659287ff8d2a2a956deff",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "e7307aa6e9706b17611262df5ae9ad6c3b07a7e770d993420b560e8abe3d5845cf1e97d14c106d86d9c792794db0236e1a29c75e10e156fdd745a6d6d0aba1df",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "b44a2463d53a10cc347b66e147b51963c9fe156216476005903d9f1308a79b0b799d0260944d0740ad9cdc7b2db06f7e333eeb0e3f665716d26dd509214f30aa",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "f057b683f03f88102bdeb81410efe173ffa10cedcf091550495aa5979b55b1c59b3c838ef1741a59ee5125dd19fc19f1216e920752ec8da82a76112025c46f6b",
        },
    };

    for (const auto &tv : tvs) {
        auto key      = hex(tv.key);
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out_single(expected.size());
        std::vector<uint8_t> out_split(expected.size());
        HMAC<SHA512_HASH> hmac;

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