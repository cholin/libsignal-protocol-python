from cffi import lib, RefCountedPointer
from buffer import Buffer
from curve import EcPublicKey

class CiphertextMsg(RefCountedPointer):
    cdecl = 'ciphertext_message*'

    @property
    def type(self):
        return lib.ciphertext_message_get_type(self.ptr)

    def serialize(self):
        return Buffer.fromptr(lib.ciphertext_message_get_serialized(self.ptr))


class SignalMsg(RefCountedPointer):
    cdecl = 'signal_message*'

    # TODO: add context

    def __copy__(self):
        copied = SignalMsg()
        lib.signal_message_copy(self._ptr, self.value, self.ctx.value)
        return copied

    @property
    def sender_ratchet_public_key(self):
        pub_key = EcPublicKey()
        pub_key.ptr = lib.signal_message_get_sender_ratchet_key(self.ptr)
        return pub_key

    @property
    def version(self):
        return lib.signal_message_get_message_version(self.ptr)

    @property
    def counter(self):
        return lib.signal_message_get_counter(self.ptr)

    @property
    def body(self):
        return Buffer.fromptr(lib.signal_message_get_body(self.ptr))

# int signal_message_is_legacy(const uint8_t *data, size_t len);
    @property
    def is_legacy(self):
        pass


# /**
#  * Verify the MAC on the Signal message.
#  *
#  * @return 1 if verified, 0 if invalid, negative on error
#  */
# int signal_message_verify_mac(signal_message *message,
#         ec_public_key *sender_identity_key,
#         ec_public_key *receiver_identity_key,
#         const uint8_t *mac_key, size_t mac_key_len,
#         signal_context *global_context);
    def verify(self):
        pass


    @classmethod
    def deserialize(cls, ctx, serialized):
        msg = SignalMsg()
        lib.signal_message_deserialize(msg._ptr,
                                       serialized.data, len(serialized),
                                       ctx.value)
        return msg

# int signal_message_create(signal_message **message, uint8_t message_version,
#         const uint8_t *mac_key, size_t mac_key_len,
#         ec_public_key *sender_ratchet_key, uint32_t counter, uint32_t previous_counter,
#         const uint8_t *ciphertext, size_t ciphertext_len,
#         ec_public_key *sender_identity_key, ec_public_key *receiver_identity_key,
#         signal_context *global_context);
    @classmethod
    def create(cls):
        pass



class PreKeySignalMsg(RefCountedPointer):
    cdecl = 'pre_key_signal_message *'

    @property
    def version(self):
        return lib.pre_key_signal_message_get_message_version(self.ptr)

    @property
    def registration_id(self):
        return lib.pre_key_signal_message_get_registration_id(self.ptr)

    @property
    def identity_pub_key(self):
        pub_key = EcPublicKey()
        pub_key.ptr = lib.pre_key_signal_message_get_identity_key(self.ptr)
        return pub_key

    def has_pre_key_id(self):
        return lib.pre_key_signal_message_has_pre_key_id(self.ptr) == 0

    @property
    def pre_key_id(self):
        if self.has_pre_key_id():
            return lib.pre_key_signal_message_get_pre_key_id(self.ptr)

    @property
    def signed_pre_key_id(self):
        return lib.pre_key_signal_message_get_signed_pre_key_id(self.ptr)

    @property
    def base_key(self):
        base_key = EcPublicKey()
        base_key.ptr = lib.pre_key_signal_message_get_base_key(self.ptr)
        return base_key

    @property
    def message(self):
        msg = SignalMsg()
        msg.ptr = lib.pre_key_signal_message_get_signal_message(self.ptr)
        return msg

    @classmethod
    def deserialize(cls, ctx, serialized):
        msg = PreKeySignalMsg()
        lib.pre_key_signal_message_deserialize(msg._ptr,
                                               serialized.data, len(serialized),
                                               ctx.value)
        return msg



# int pre_key_signal_message_create(pre_key_signal_message **pre_key_message,
#         uint8_t message_version, uint32_t registration_id, const uint32_t *pre_key_id,
#         uint32_t signed_pre_key_id, ec_public_key *base_key, ec_public_key *identity_key,
#         signal_message *message,
#         signal_context *global_context);

# int pre_key_signal_message_deserialize(pre_key_signal_message **message,
#         const uint8_t *data, size_t len,
#         signal_context *global_context);

# int pre_key_signal_message_copy(pre_key_signal_message **message, pre_key_signal_message *other_message, signal_context *global_context);

# signal_message *pre_key_signal_message_get_signal_message(const pre_key_signal_message *message);
