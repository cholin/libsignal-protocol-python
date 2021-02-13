def register_crypto_callbacks(ffibuilder):
    # random
    ffibuilder.cdef("""
extern "Python" int random_func(uint8_t *data, size_t data_len, void *user_data);
    """)

    # hashes
    ffibuilder.cdef("""
extern "Python" int hmac_sha256_init_func(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
extern "Python" int hmac_sha256_update_func(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
extern "Python" int hmac_sha256_final_func(void *hmac_context, signal_buffer **output, void *user_data);
extern "Python" void hmac_sha256_cleanup_func(void *hmac_context, void *user_data);

extern "Python" int sha512_digest_init_func(void **digest_context, void *user_data);
extern "Python" int sha512_digest_update_func(void *digest_context, const uint8_t *data, size_t data_len, void *user_data);
extern "Python" int sha512_digest_final_func(void *digest_context, signal_buffer **output, void *user_data);
extern "Python" void sha512_digest_cleanup_func(void *digest_context, void *user_data);
    """)

    # aes
    ffibuilder.cdef("""
extern "Python" int encrypt_func(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data);
extern "Python" int decrypt_func(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data);
    """)

    # crypto_provider
    ffibuilder.cdef("""
typedef struct signal_crypto_provider {
    int (*random_func)(uint8_t *data, size_t len, void *user_data);

    // sha256
    int (*hmac_sha256_init_func)(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
    int (*hmac_sha256_update_func)(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
    int (*hmac_sha256_final_func)(void *hmac_context, signal_buffer **output, void *user_data);
    void (*hmac_sha256_cleanup_func)(void *hmac_context, void *user_data);

    // sha512
    int (*sha512_digest_init_func)(void **digest_context, void *user_data);
    int (*sha512_digest_update_func)(void *digest_context, const uint8_t *data, size_t data_len, void *user_data);
    int (*sha512_digest_final_func)(void *digest_context, signal_buffer **output, void *user_data);
    void (*sha512_digest_cleanup_func)(void *digest_context, void *user_data);

    // AES
    int (*encrypt_func)(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data);
    int (*decrypt_func)(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data);

    // User data
    void *user_data;
} signal_crypto_provider;
    """)
