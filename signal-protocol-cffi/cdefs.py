import sys
import os
import subprocess
import sysconfig
from cffi import FFI
from pathlib import Path

module_dir = Path(__file__).parent

lib_name = 'signal-protocol-c'
lib_header_filename = 'libsignal-protocol-c.h'

path_dirs = [Path(p) for p in sys.path] + [module_dir]
include_dirs = [str(p/'include'/'signal') for p in path_dirs]+ [str(module_dir / 'stubs')]
lib_dirs = [str(p/'lib') for p in path_dirs]

ffibuilder = FFI()

# defines are exposed as enums
ffibuilder.cdef("""
enum {
    SG_SUCCESS=0,
    SG_ERR_NOMEM=-12,   /* Not enough space */
    SG_ERR_INVAL=-22,   /* Invalid argument */
    /* Custom error codes for error conditions specific to the library */
    SG_ERR_UNKNOWN=             -1000,
    SG_ERR_DUPLICATE_MESSAGE=   -1001,
    SG_ERR_INVALID_KEY=         -1002,
    SG_ERR_INVALID_KEY_ID=      -1003,
    SG_ERR_INVALID_MAC=         -1004,
    SG_ERR_INVALID_MESSAGE=     -1005,
    SG_ERR_INVALID_VERSION=     -1006,
    SG_ERR_LEGACY_MESSAGE=      -1007,
    SG_ERR_NO_SESSION=          -1008,
    SG_ERR_STALE_KEY_EXCHANGE=  -1009,
    SG_ERR_UNTRUSTED_IDENTITY=  -1010,
    SG_ERR_VRF_SIG_VERIF_FAILED=-1011,
    SG_ERR_INVALID_PROTO_BUF=   -1100,
    SG_ERR_FP_VERSION_MISMATCH= -1200,
    SG_ERR_FP_IDENT_MISMATCH=   -1201,
    SG_ERR_MINIMUM=             -9999
};

enum {
    SG_LOG_ERROR=  0,
    SG_LOG_WARNING=1,
    SG_LOG_NOTICE= 2,
    SG_LOG_INFO=   3,
    SG_LOG_DEBUG=  4
};

// session_cipher.h
enum {
    SG_CIPHER_AES_CTR_NOPADDING=1,
    SG_CIPHER_AES_CBC_PKCS5=2
};

// protocol.h
enum {
    KEY_EXCHANGE_INITIATE_FLAG=0x01,
    KEY_EXCHANGE_RESPONSE_FLAG=0X02,
    KEY_EXCHANGE_SIMULTAENOUS_INITIATE_FLAG=0x04
};

enum {
    CIPHERTEXT_UNSUPPORTED_VERSION=1,
    CIPHERTEXT_CURRENT_VERSION=3
};

enum {
    CIPHERTEXT_SIGNAL_TYPE=2,
    CIPHERTEXT_PREKEY_TYPE=3,
    CIPHERTEXT_SENDERKEY_TYPE=4,
    CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE=5
};

/* Worst case overhead. Not always accurate, but good enough for padding. */
enum { CIPHERTEXT_ENCRYPTED_MESSAGE_OVERHEAD=53};
""")

# dynamically load declarations by running only the preprocessor of your
# c compiler (with no std includes + providing stub files for includes)
filename = module_dir / lib_header_filename
include_dir_args = ['-I{}/'.format(i) for i in include_dirs]
args = ['-CC', '-nostdinc', '-E', str(filename)] + include_dir_args
prog = sysconfig.get_config_var('CC').split(' ')
print(prog, args)
with subprocess.Popen(prog+args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
    declarations = proc.stdout.read().decode('utf-8')
    print(proc.stderr.read())
    ffibuilder.cdef(declarations)

# Python callables (for struct callbacks)
ffibuilder.cdef("""
extern "Python" void destroy_func(void *user_data);

extern "Python" int get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data);
extern "Python" int get_local_registration_id(uint32_t *registration_id, void *user_data);
extern "Python" int save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);
extern "Python" int is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);

extern "Python" int load_session_func(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data);
extern "Python" int get_sub_device_sessions_func(signal_int_list **sessions, const char *name, size_t name_len, void *user_data);
extern "Python" int store_session_func(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);
extern "Python" int contains_session_func(const signal_protocol_address *address, void *user_data);
extern "Python" int delete_session_func(const signal_protocol_address *address, void *user_data);
extern "Python" int delete_all_sessions_func(const char *name, size_t name_len, void *user_data);

extern "Python" int load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data);
extern "Python" int store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
extern "Python" int contains_pre_key(uint32_t pre_key_id, void *user_data);
extern "Python" int remove_pre_key(uint32_t pre_key_id, void *user_data);

extern "Python" int load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data);
extern "Python" int store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);
extern "Python" int contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data);
extern "Python" int remove_signed_pre_key(uint32_t signed_pre_key_id, void *user_data);

extern "Python" int store_sender_key(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);
extern "Python" int load_sender_key(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data);

extern "Python" void signal_lock(void *user_data);
extern "Python" void signal_unlock(void *user_data);
extern "Python" void signal_log(int level, const char *message, size_t len, void *user_data);

extern "Python" int random_func(uint8_t *data, size_t data_len, void *user_data);

extern "Python" int hmac_sha256_init_func(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
extern "Python" int hmac_sha256_update_func(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
extern "Python" int hmac_sha256_final_func(void *hmac_context, signal_buffer **output, void *user_data);
extern "Python" void hmac_sha256_cleanup_func(void *hmac_context, void *user_data);

extern "Python" int sha512_digest_init_func(void **digest_context, void *user_data);
extern "Python" int sha512_digest_update_func(void *digest_context, const uint8_t *data, size_t data_len, void *user_data);
extern "Python" int sha512_digest_final_func(void *digest_context, signal_buffer **output, void *user_data);
extern "Python" void sha512_digest_cleanup_func(void *digest_context, void *user_data);

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