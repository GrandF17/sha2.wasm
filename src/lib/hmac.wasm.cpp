#include <emscripten/emscripten.h>

#include "hmac.class.cpp"
#include "sha224.class.cpp"
#include "sha256.class.cpp"
#include "sha384.class.cpp"
#include "sha512.class.cpp"


extern "C" {
    /** HMAC for SHA224 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha224(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA224_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };

    /** HMAC for SHA256 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha256(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA256_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };

    /** HMAC for SHA384 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha384(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA384_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };

    /** HMAC for SHA512 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha512(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA512_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };
};