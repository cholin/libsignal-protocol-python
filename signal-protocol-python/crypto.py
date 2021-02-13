from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from abc import ABC, abstractmethod
from cffi import ffi, lib, StructBinder


class CryptoProvider(StructBinder, ABC):
    cdecl = 'signal_crypto_provider*'

    @abstractmethod
    def random_func(self, data, data_len):
        pass

    #
    # HMAC-SHA256
    #
    @abstractmethod
    def hmac_sha256_init_func(self, hmac_context, key, key_len):
        pass

    @abstractmethod
    def hmac_sha256_update_func(self, hmac_context, data, data_len):
        pass

    @abstractmethod
    def hmac_sha256_final_func(self, hmac_context, output):
        pass

    @abstractmethod
    def hmac_sha256_cleanup_func(self, hmac_context):
        pass

    #
    # SHA512
    #
    @abstractmethod
    def sha512_digest_init_func(self, digest_context):
        pass

    @abstractmethod
    def sha512_digest_update_func(self, digest_context, data, data_len):
        pass

    @abstractmethod
    def sha512_digest_final_func(self, digest_context, output):
        pass

    @abstractmethod
    def sha512_digest_cleanup_func(self, digest_context):
        pass

    #
    # AES
    #
    @abstractmethod
    def encrypt_func(self, output, cipher, key, key_len, iv, iv_len, plaintext, plaintext_len):
        pass

    @abstractmethod
    def decrypt_func(self, output, cipher, key, key_len, iv, iv_len, ciphertext, ciphertext_len):
        pass


class CryptoPyProvider(CryptoProvider):
    handles = []  # used to keep python object alive (as these methods are
                  # called in c context and would otherwise be garbage
                  # collected)

    def random_func(self, data, data_len):
        ffi.memmove(data, get_random_bytes(data_len), data_len)
        return 0

    #
    # HMAC-SHA256
    #
    def hmac_sha256_init_func(self, hmac_context, key, key_len):
        hmac = HMAC.new(ffi.buffer(key, key_len)[:], digestmod=SHA256)
        handle = ffi.new_handle(hmac)
        hmac_context[0] = handle
        self.handles.append(handle)
        return 0

    def hmac_sha256_update_func(self, hmac_context, data, data_len):
        hmac = ffi.from_handle(hmac_context)
        hmac.update(ffi.buffer(data, data_len)[:])
        return 0

    def hmac_sha256_final_func(self, hmac_context, output):
        hmac = ffi.from_handle(hmac_context)
        digest = hmac.digest()
        output[0] = lib.signal_buffer_create(digest, len(digest))
        return 0

    def hmac_sha256_cleanup_func(self, hmac_context):
        self.handles.remove(hmac_context)

    #
    # SHA512
    #
    def sha512_digest_init_func(self, digest_context):
        sha512 = SHA512.new()
        handle = ffi.new_handle(sha512)
        digest_context[0] = handle
        self.handles.append(handle)
        return 0

    def sha512_digest_update_func(self, digest_context, data, data_len):
        sha512 = ffi.from_handle(digest_context)
        sha512.update(ffi.buffer(data, data_len))
        return 0

    def sha512_digest_final_func(self, digest_context, output):
        sha512 = ffi.from_handle(digest_context)
        digest = sha512.digest()
        output[0] = lib.signal_buffer_create(digest, len(digest))
        return 0

    def sha512_digest_cleanup_func(self, digest_context):
        self.handles.remove(digest_context)

    #
    # AES
    #
    def encrypt_func(self, output, cipher, key, key_len, iv, iv_len, plaintext, plaintext_len):
        k = ffi.buffer(key, key_len)[:]
        i = ffi.buffer(iv, iv_len)[:]
        m = ffi.buffer(plaintext, plaintext_len)[:]

        # default to SG_CIPHER_AES_CTR_NOPADDING
        mode = AES.MODE_CTR
        padding = id
        if (cipher == lib.SG_CIPHER_AES_CBC_PKCS5):
            mode = AES.MODE_CBC
            padding = lambda x: pad(x, 16)

        cipher = AES.new(k, mode, i)
        padded = padding(m)
        ciphertext = cipher.encrypt(padded)
        output[0] = lib.signal_buffer_create(ciphertext, len(ciphertext))

        return 0

    def decrypt_func(self, output, cipher, key, key_len, iv, iv_len, ciphertext, ciphertext_len):
        k = ffi.buffer(key, key_len)[:]
        i = ffi.buffer(iv, iv_len)[:]
        c = ffi.buffer(ciphertext, ciphertext_len)[:]

        # default to SG_CIPHER_AES_CTR_NOPADDING
        mode = AES.MODE_CTR
        unpadding = id
        if (cipher == lib.SG_CIPHER_AES_CBC_PKCS5):
            mode = AES.MODE_CBC
            unpadding = lambda x: unpad(x, 16)

        cipher = AES.new(k, mode, i)
        plaintext = cipher.decrypt(c)
        unpadded = unpadding(plaintext)
        output[0] = lib.signal_buffer_create(unpadded, len(unpadded))

        return 0
