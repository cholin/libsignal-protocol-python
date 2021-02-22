from .cffi import ffi, RefCountedPointer, invoke
from .buffer import Buffer
from .curve import EcPublicKey, EcPrivateKey, EcKeyPair
from datetime import datetime


class RatchetIdentityKeyPair(RefCountedPointer):
    cdecl = 'ratchet_identity_key_pair*'

    def __eq__(self, other):
        return self.private_key == other.private_key and \
               self.public_key == other.public_key

    @property
    def public_key(self):
        pub_key = EcPublicKey()
        pub_key.ptr = invoke('ratchet_identity_key_pair_get_public', self.ptr)
        return pub_key

    @property
    def private_key(self):
        priv_key = EcPrivateKey()
        priv_key.ptr = invoke('ratchet_identity_key_pair_get_private',
                              self.ptr)
        return priv_key

    @property
    def key_pair(self):
        return EcKeyPair.create(self.public_key, self.private_key)

    def serialize(self):
        buffer = Buffer()
        invoke('ratchet_identity_key_pair_serialize', buffer._ptr, self.ptr)
        return buffer

    @classmethod
    def deserialize(cls, ctx, serialized):
        key_pair = RatchetIdentityKeyPair()
        invoke('ratchet_identity_key_pair_deserialize', key_pair._ptr,
               serialized.data, len(serialized), ctx.value)
        return key_pair

    @classmethod
    def create(cls, key_pair):
        identity = RatchetIdentityKeyPair()
        invoke('ratchet_identity_key_pair_create', identity._ptr,
               key_pair.public_key.ptr, key_pair.private_key.ptr)
        return identity

    @classmethod
    def generate(cls, ctx):
        key_pair = RatchetIdentityKeyPair()
        invoke('signal_protocol_key_helper_generate_identity_key_pair',
               key_pair._ptr, ctx.value)
        return key_pair


class SessionPreKey(RefCountedPointer):
    cdecl = 'session_pre_key*'

    def __eq__(self, other):
        return self.id == other.id

    @property
    def id(self):
        return invoke('session_pre_key_get_id', self.ptr)

    @property
    def public_key(self):
        return self.key_pair.public_key

    @property
    def key_pair(self):
        key_pair = EcKeyPair(self.id)
        key_pair.ptr = invoke('session_pre_key_get_key_pair', self.ptr)
        return key_pair

    def serialize(self):
        buffer = Buffer()
        invoke('session_pre_key_serialize', buffer._ptr, self.ptr)
        return buffer

    @classmethod
    def deserialize(cls, ctx, serialized):
        pre_key = SessionPreKey()
        invoke('session_pre_key_deserialize', pre_key._ptr, serialized.data,
               len(serialized), ctx.value)
        return pre_key

    @classmethod
    def create(cls, id, key_pair):
        pre_key = SessionPreKey()
        invoke('session_pre_key_create', pre_key._ptr, id, key_pair.ptr)
        return pre_key

    @classmethod
    def generate(cls, ctx, start=1, count=100):
        pre_key_list_cdecl = 'signal_protocol_key_helper_pre_key_list_node **'
        pre_key_list = ffi.new(pre_key_list_cdecl)
        invoke('signal_protocol_key_helper_generate_pre_keys', pre_key_list,
               start, count, ctx.value)
        node = pre_key_list[0]
        while node != ffi.NULL:
            pre_key = SessionPreKey()
            pre_key.ptr = invoke('signal_protocol_key_helper_key_list_element',
                                 node)
            yield pre_key
            node = invoke('signal_protocol_key_helper_key_list_next', node,
                          nullable=True)
        invoke('signal_protocol_key_helper_key_list_free', pre_key_list[0])


class SessionSignedPreKey(RefCountedPointer):
    cdecl = 'session_signed_pre_key*'

    def __eq__(self, other):
        return self.id == other.id

    @property
    def id(self):
        return invoke('session_signed_pre_key_get_id', self.ptr)

    @property
    def timestamp(self):
        ts = invoke('session_signed_pre_key_get_timestamp', self.ptr)
        return datetime.fromtimestamp(ts)

    @property
    def signed_pub_key(self):
        pub_key = self.key_pair.public_key
        pub_key.signature = self.signature
        return pub_key

    @property
    def key_pair(self):
        key_pair = EcKeyPair(self.id)
        key_pair.ptr = invoke('session_signed_pre_key_get_key_pair', self.ptr)
        return key_pair

    @property
    def signature(self):
        signature = invoke('session_signed_pre_key_get_signature', self.ptr)
        size = invoke('session_signed_pre_key_get_signature_len', self.ptr)
        return Buffer.create(signature, size)

    def serialize(self):
        buffer = Buffer()
        invoke('session_signed_pre_key_serialize', buffer._ptr, self.ptr)
        return buffer

    @classmethod
    def deserialize(cls, ctx, serialized):
        signed_pre_key = SessionSignedPreKey()
        invoke('session_signed_pre_key_deserialize', signed_pre_key._ptr,
               serialized.data, len(serialized), ctx.value)
        return signed_pre_key

    @classmethod
    def create(cls, id, datetime, key_pair, signature):
        signed_pre_key = SessionSignedPreKey()
        timestamp = int(datetime.timestamp())
        invoke('session_signed_pre_key_create', signed_pre_key._ptr, id,
               timestamp, key_pair.ptr, signature.data, len(signature))
        return signed_pre_key

    @classmethod
    def generate(cls, ctx, identity_key_pair, id):
        signed_pre_key = SessionSignedPreKey()
        timestamp = datetime.now().timestamp()

        invoke('signal_protocol_key_helper_generate_signed_pre_key',
               signed_pre_key._ptr, identity_key_pair.ptr, id, int(timestamp),
               ctx.value)

        return signed_pre_key


class SessionPreKeyBundle(RefCountedPointer):
    cdecl = 'session_pre_key_bundle*'

    @property
    def registration_id(self):
        return invoke('session_pre_key_bundle_get_registration_id', self.ptr)

    @property
    def device_id(self):
        return invoke('session_pre_key_bundle_get_device_id', self.ptr)

    @property
    def pub_pre_key(self):
        key_id = invoke('session_pre_key_bundle_get_pre_key_id', self.ptr)
        pre_key = EcPublicKey(key_id)
        pre_key.ptr = invoke('session_pre_key_bundle_get_pre_key', self.ptr)
        return pre_key

    @property
    def signed_pub_pre_key(self):
        key_id = invoke('session_pre_key_bundle_get_signed_pre_key_id',
                        self.ptr)
        signed_pre_key = EcPublicKey(key_id)
        signed_pre_key.ptr = invoke('session_pre_key_bundle_get_signed_pre_key',
                                    self.ptr)

        signature = Buffer()
        buf = invoke('session_pre_key_bundle_get_signed_pre_key_signature',
                     self.ptr)
        signature._ptr[0] = invoke('signal_buffer_copy', buf)
        signed_pre_key.signature = signature

        return signed_pre_key

    @property
    def pub_identity_key(self):
        identity_key = EcPublicKey()
        identity_key.ptr = invoke('session_pre_key_bundle_get_identity_key',
                                  self.ptr)
        return identity_key

    @classmethod
    def create(cls, registration_id, device_id, identity_pub_key,
               signed_pub_pre_key, pub_pre_key):
        identity_pub_key.verify(signed_pub_pre_key.serialize(),
                                signed_pub_pre_key.signature)

        bundle = SessionPreKeyBundle()
        signature = signed_pub_pre_key.signature
        invoke('session_pre_key_bundle_create', bundle._ptr, registration_id,
               device_id, pub_pre_key.id, pub_pre_key.ptr,
               signed_pub_pre_key.id, signed_pub_pre_key.ptr,
               signature.data, len(signature),
               identity_pub_key.ptr)
        return bundle
