from cffi import ffi, lib, Pointer
from buffer import Buffer
from messages import CiphertextMsg
from keys import SessionPreKeyBundle
from messages import PreKeySignalMsg, SignalMsg
from errors import raise_on_error


class SessionBuilder(Pointer):
    cdecl = 'session_builder**'

    def __del__(self):
        lib.session_builder_free(self.value)

    def process_pre_key_bundle(self, bundle):
        result = lib.session_builder_process_pre_key_bundle(self.value, bundle.ptr)
        raise_on_error(result)
        return result == lib.SG_SUCCESS

    @classmethod
    def create(cls, ctx, store, address):
        builder = SessionBuilder()
        builder.address = address
        result = lib.session_builder_create(builder._ptr, store.value, builder.address.ptr, ctx.value)
        raise_on_error(result)
        return builder


class SessionCipher(Pointer):
    cdecl = 'session_cipher**'

    def __del__(self):
        lib.session_cipher_free(self.value)

    @property
    def version(self):
        uint32 = ffi.new('uint32_t*')
        result = lib.session_cipher_get_session_version(self.value, uint32)
        raise_on_error(result)
        return uint32[0]

    @property
    def remote_registstration_id(self):
        uint32 = ffi.new('uint32_t*')
        lib.session_cipher_get_remote_registration_id(self.value, uint32)
        return uint32[0]

    def encrypt(self, message):
        ciphertext = CiphertextMsg()
        lib.session_cipher_encrypt(self.value, message.data, len(message), ciphertext._ptr)
        return ciphertext
    
    def decrypt(self, ciphertext):
        plaintext = Buffer()
        result = lib.session_cipher_decrypt_signal_message(self.value, ciphertext.ptr, ffi.NULL, plaintext._ptr)
        raise_on_error(result)
        return plaintext

    def decrypt_pre_key_signal_msg(self, ciphertext):
        plaintext = Buffer()
        result = lib.session_cipher_decrypt_pre_key_signal_message(self.value, ciphertext.ptr, ffi.NULL, plaintext._ptr)
        raise_on_error(result)
        return plaintext

    @classmethod
    def create(cls, ctx, store, recipient):
        session = cls()
        session.address = recipient
        lib.session_cipher_create(session._ptr, store.value, session.address._ptr, ctx.value)
        return session


class Session:

    def __init__(self, ctx, store, recipient):
        self.ctx = ctx
        self.store = store
        self.recipient = recipient
        self.cipher = SessionCipher.create(ctx, store, recipient)

    @property
    def initialized(self):
        return lib.signal_protocol_session_contains_session(self.store.value, self.recipient.ptr) == 1

    def process(self, reg_id, identity_pub_key, signed_pub_pre_key, ephemeral_pub_key):
        self.store.save_identity(self.recipient, identity_pub_key)

        builder = SessionBuilder.create(self.ctx, self.store, self.recipient)

        bundle = SessionPreKeyBundle.create(reg_id, self.recipient.device_id,
                    identity_pub_key, signed_pub_pre_key,
                    ephemeral_pub_key)      
        builder.process_pre_key_bundle(bundle)

    def encrypt(self, message):
        data = Buffer.create(message)
        return self.cipher.encrypt(data)

    def decrypt(self, msg_type, serialized):
        if msg_type == lib.CIPHERTEXT_SIGNAL_TYPE:
            ciphertext = SignalMsg.deserialize(self.ctx, serialized)
            return self.cipher.decrypt(ciphertext)
        ciphertext = PreKeySignalMsg.deserialize(self.ctx, serialized)
        return self.cipher.decrypt_pre_key_signal_msg(ciphertext)