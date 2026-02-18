#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/hmac.class.cpp"
#include "../lib/sha384.class.cpp"


struct TV {
    const char *key;
    const char *message;
    const char *hash;
};

TEST(HMAC, SHA384) {
    const TV tvs[] = {
        /** empty string (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "",
            "7bee4557700a1d8ece045e8a6fc980f456d2ff4f5aa77bea3147f54dc77e8f6a2fa016e9baa4e105d53b4631ce088cbe",
        },
        /** ASCII "abc" (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "616263",
            "67bf47cd4b410564245d335985b5dd404d085e2db88f2a35b0782c7fa4aef3407d489d66ea8914e74752cd1913963139",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "34b80b9f2775dabb019819277302adaeec0ca6f0963b2979314a44724b6318d9213ddffa2e04b175e1e7d6778fc8a8a5",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "9167a02335b2d06447f738b290232526b18ff400bc2e3104faee7c279c807d6c7a9ad3e568531c49f4191603b729a709",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (short key) */
        {
            "00112233445566778899aabbccddeeff",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "c7ab9c4d717c6e2beb6a10ad3f2298d3ab5780ce7fb7f577840884b39d22f1ffe8d7d0588a1cfdc4aa80d7b55a99a1ba",
        },
        /** empty string (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "",
            "d2d69b69191d403c715ad3bf83fb8271ccb4de1afb5a996c07fb561ec7d292c22c3dab667ee139c782c4f927500cadcc",
        },
        /** ASCII "abc" (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "616263",
            "51be46e29804e9271a0ee35ffcf971b7552fb210602e17c6cd2bca207bcea1dd114fe7590c88bb769630c69a184d3058",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "0e55fd9d2bdb130ce8f68c4ef06aefa392af3acbe6c67d5353892f51e7ffaf5bbd702f0595cef38ce0eff69ae1a23cf1",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "02d073985d46f07d5536e6546e8e83fd5679dfd8c1e71d35fa5346b2151562fab2b9c3b633c0a2942b64c4e6cf52fb43",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." (long key) */
        {
            "cf13a9dade8f5aa8f42286820afe14c2246266b7ebd04499f777aa958a0d59e30eedc8f89b7be9b1e519e704f23bba16ea5e88300ed0b0e95886df5a0bc2d770"
            "8b40e78ef4022c4b241abc8b1794f2c0e5d9870220d2c0b21ea721c7d6b316a316c152f0aad49ac2181adbb841c3de4b61a6237e9d850d82f044ee84a2c6182b"
            "b6",
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "2023ab19a4bea9bf7d19d4c20679c7a2422324b2fb75d299310db8ac6342af37f243abdcb2d98cab9d9a758ab269d527",
        },
    };

    for (const auto &tv : tvs) {
        auto key      = hex(tv.key);
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out_single(expected.size());
        std::vector<uint8_t> out_split(expected.size());
        HMAC<SHA384_HASH> hmac;

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