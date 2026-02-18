#include <gtest/gtest.h>

#include "utils.cpp"

#include "../lib/sha512.class.cpp"


struct TV {
    const char *message;
    const char *hash;
};

TEST(SHA2, 512) {
    const TV tvs[] = {
        {
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        },
        {
            "616263",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        },
        {
            "deadbeef",
            "1284b2d521535196f22175d5f558104220a6ad7680e78b49fa6f20e57ea7b185d71ec1edb137e70eba528dedb141f5d2f8bb53149d262932b27cf41fed96aa7f",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "77fdca421e16ebe2a2bcd585621c11d2d4dcb72e9df5d5d48a75f0417f40d215569c25f00851ffed130cc540be281b6acdac96bd83d71631fce573ac6e01e9f0",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "deadbeef",
            "9006f02ae6f4cbaf25cb706534e9964a3b74fe71484f54ef52290d0f5ec4c4a9b00312032860d99d70023b9ffbd60a9008f4660730cce6a19d5ca87f9625ff41",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ad9cfb3647ce83e212a17968a8c94093842cf99418743674ded043f68eb2dbf0677fab38e1afb16cda3229a572ba41c13dd575296fb943e21ebf589a00d0dcaa",
        },
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "8bab5dd8b15e849f54f16f9309f260524436190b926f4343c340401c3acbb68b584782361dba5c5ac15909ace5a69db50ab6c9efb5f08f7faa8d8aad891ed307",
        },
        /** ASCII "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
        {
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog" */
        {
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
        },
        /** ASCII "The quick brown fox jumps over the lazy dog." */
        {
            "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
            "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
        },
        /** boundary: single zero byte */
        {
            "00",
            "b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee",
        },
        /** boundary: 120 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899010203040506"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
            "8c1c048876fd2b36f6f9c44d773fa8e22a5b3c44450ca0fe728c533f1a7248c7ce60d359f532e092dac5aa616281e32287be1393b2c72fa038c37a65b5af8d9f",
        },
        /** boundary: 127 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899010203040506"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990102030405",
            "c6f3fd2b3d0c04f0eb7200936c75b43b78ac142a28ce50731620c26451c3ea9a78384d39114919e1ce402debc16d9505cd35910368c7c1efee9c264e0564d4aa",
        },
        /** boundary: 128 bytes */
        {
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899010203040506"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899010203040506",
            "374c1be3139293b51266e3141cdb2e39ff6cc901f4bf1cd4d79fdb5703d29d67dfb2a27aea9a36daabab90e1750a5f2e4516f83cb1bc9c8785054b09b25d89ff",
        },
    };

    for (const auto &tv : tvs) {
        auto message  = hex(tv.message);
        auto expected = hex(tv.hash);

        std::vector<uint8_t> out_single(expected.size());
        std::vector<uint8_t> out_split(expected.size());
        SHA512_HASH H;

        /** single-shot */
        {
            H.init();
            H.update(message.data(), message.size());
            H.digest(out_single.data());
            H.destroy();
        }

        /** two-shots */
        {
            H.init();

            size_t half = message.size() / 2;

            H.update(message.data(), half);
            H.update(message.data() + half, message.size() - half);

            H.digest(out_split.data());
            H.destroy();
        }

        EXPECT_EQ(out_single, expected);
        EXPECT_EQ(out_split, expected);
        EXPECT_EQ(out_single, out_split);
    };
};