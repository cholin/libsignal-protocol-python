from cffi import FFI
from .base_types import register_base_types
from .buffer import register_buffer
from .buffer_list import register_buffer_list
from .ratchet import register_ratchet
from .curve import register_curve
from .session_record import register_session_record
from .session_prekey import register_session_prekey
from .sender_key_record import register_sender_key_record
from .crypto_provider import register_crypto_callbacks
from .stores import register_store_callbacks
from .context import register_context_callbacks
from .key_helper import register_key_helper
from .session_builder import register_session_builder
from .session_cipher import register_session_cipher
from .protocol import register_protocol


ffi = FFI()

# error codes
ffi.cdef("""
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
    """)

# log levels
ffi.cdef("""
enum {
    SG_LOG_ERROR=  0,
    SG_LOG_WARNING=1,
    SG_LOG_NOTICE= 2,
    SG_LOG_INFO=   3,
    SG_LOG_DEBUG=  4
};
""")

# ciphers
ffi.cdef("""
enum {
    SG_CIPHER_AES_CTR_NOPADDING=1,
    SG_CIPHER_AES_CBC_PKCS5=2
};
""")

register_base_types(ffi)         # signal_protocol_types.h
register_buffer(ffi)
register_buffer_list(ffi)

# ref counting
ffi.cdef("""
void signal_type_ref(signal_type_base *instance);
void signal_type_unref(signal_type_base *instance);
""")

register_ratchet(ffi)            # ratchet.h
register_curve(ffi)              # curve.h
register_session_record(ffi)     # session_record.h
register_session_prekey(ffi)     # session_prey_key.h
register_sender_key_record(ffi)  # sender_key_record.h
register_crypto_callbacks(ffi)
register_store_callbacks(ffi)
register_context_callbacks(ffi)
register_key_helper(ffi)
register_session_builder(ffi)
register_session_cipher(ffi)
register_protocol(ffi)

# c stdlib stuff
ffi.cdef("""
void *malloc(size_t size);
void free(void *ptr);
""")
