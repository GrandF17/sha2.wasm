#ifndef HMAC_HPP
#define HMAC_HPP


#include <cstdint>
#include <cstring>


template<class Hash> 
class HMAC {
private:
    /** hash-function */
    Hash H;

    /** ikey XOR shared secret for HMAC */
    uint8_t ikey[Hash::block_size];

    /** okey XOR shared secret for HMAC */
    uint8_t okey[Hash::block_size];

public:
    /** predefined constant inner padding */
    static constexpr uint8_t IPAD = 0x36;

    /** predefined constant outter padding */
    static constexpr uint8_t OPAD = 0x5c;

    /** block size according to Hash class */
    static constexpr size_t block_size  = Hash::block_size;

    /** digest result size according to Hash class */
    static constexpr size_t digest_size = Hash::digest_size;

    void init(const uint8_t* key, size_t key_len) {
        uint8_t secret[block_size] = {0};

        if (key_len > block_size) {
            /** if secret size > block size */
            H.init();
            H.update(key, key_len);
            H.digest(secret);
            H.destroy();
        } else {
            /** if secret size <= block size */
            memcpy(secret, key, key_len);
        };
        
        /** create ikey + okey */
        for (size_t i = 0; i < block_size; ++i) {
            ikey[i] = secret[i] ^ IPAD;
            okey[i] = secret[i] ^ OPAD;
        };

        /** secure zeroization of secret */
        explicit_bzero(secret, sizeof(secret));

        /** init state with ikey */
        H.init();
        H.update(ikey, sizeof(ikey));
    };

    void update(const uint8_t *message, size_t len) {
        H.update(message, len);
    };

    void digest(uint8_t *out) {
        H.digest(out);
        H.destroy();

        H.init();
        H.update(okey, block_size);
        H.update(out, digest_size);
        H.digest(out);
        H.destroy();
    };

    void destroy() {
        /** destroy hash-function */
        H.destroy();

        /** secure zeroization of ikey + okey */
        Utils::Clean::secure_zero(ikey, sizeof(ikey));
        Utils::Clean::secure_zero(okey, sizeof(okey));
    };
};  // HMAC class


#endif  // HMAC_HPP