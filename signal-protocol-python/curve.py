from cffi import lib, RefCountedPointer
from buffer import Buffer


class EcPublicKey(RefCountedPointer):
    cdecl = 'ec_public_key*'

    def __init__(self, key_id=None):
        super(EcPublicKey, self).__init__()
        self.id = key_id

    def __eq__(self, other):
        return lib.ec_public_key_compare(self.ptr, other.ptr) == 0

    def serialize(self):
        buffer = Buffer()
        lib.ec_public_key_serialize(buffer._ptr, self.ptr)
        return buffer

    def verify(self, content, signature):
        result = lib.curve_verify_signature(self.ptr,
                                            content.data, len(content),
                                            signature.data, len(signature))
        if result != 1:
            raise ValueError("invalid signature")

        return True

    def verify_vrf(self, ctx, content, signature):
        vrf_output = Buffer()
        result = lib.curve_verify_vrf_signature(ctx.value, vrf_output._ptr, self.ptr,
                                                content.data, len(content),
                                                signature.data, len(signature))
        if result != 0:
            raise ValueError("invalid vrf signature")

        return vrf_output

    @classmethod
    def decode_point(cls, ctx, point, key_id=None):
        pub_key = EcPublicKey(key_id)
        lib.curve_decode_point(pub_key._ptr, point.data, len(point), ctx.value)
        return pub_key

    @classmethod
    def generate(cls, priv_key, key_id=None):
        pub_key = EcPublicKey(key_id)
        lib.curve_generate_public_key(pub_key._ptr, priv_key.ptr)
        return pub_key


class EcPrivateKey(RefCountedPointer):
    cdecl = 'ec_private_key*'

    def __init__(self, key_id=None):
        super(EcPrivateKey, self).__init__()
        self.key_id = key_id

    def __eq__(self, other):
        return lib.ec_private_key_compare(self.ptr, other.ptr) == 0

    def serialize(self):
        buffer = Buffer()
        lib.ec_private_key_serialize(buffer._ptr, self.ptr)
        return buffer

    def sign(self, ctx, content):
        signature = Buffer()
        result = lib.curve_calculate_signature(ctx.value, signature._ptr, self.ptr,
                                               content.data, len(content))
        if result != 0:
            raise ValueError("could not calculate signature")
        return signature

    def sign_vrf(self, ctx, content):
        signature = Buffer()
        result = lib.curve_calculate_vrf_signature(ctx.value, signature._ptr,
                                                   self.ptr,
                                                   content.data, len(content))
        if result != 0:
            raise ValueError("could not calculate signature")
        return signature

    @classmethod
    def decode_point(cls, ctx, point, key_id=None):
        priv_key = EcPrivateKey(key_id)
        lib.curve_decode_private_point(
            priv_key._ptr, point.data, len(point), ctx.value)
        return priv_key

    @classmethod
    def generate(cls, ctx, key_id=None):
        priv_key = EcPrivateKey(key_id)
        lib.curve_generate_private_key(ctx.value, priv_key._ptr)
        return priv_key


class EcKeyPair(RefCountedPointer):
    cdecl = 'ec_key_pair*'

    def __init__(self, key_id=None):
        super(EcKeyPair, self).__init__()
        self.key_id = key_id

    def __eq__(self, other):
        return self.private_key == other.private_key and \
               self.public_key == other.public_key

    @property
    def public_key(self):
        pub_key = EcPublicKey(self.key_id)
        pub_key.ptr = lib.ec_key_pair_get_public(self.ptr)
        return pub_key

    @property
    def private_key(self):
        priv_key = EcPrivateKey(self.key_id)
        priv_key.ptr = lib.ec_key_pair_get_private(self.ptr)
        return priv_key

    @classmethod
    def create(cls, public_key, private_key, key_id=None):
        key_pair = EcKeyPair(key_id)
        lib.ec_key_pair_create(key_pair._ptr, public_key.ptr, private_key.ptr)
        return key_pair

    @classmethod
    def generate(cls, ctx, key_id=None):
        key_pair = EcKeyPair(key_id)
        lib.curve_generate_key_pair(ctx.value, key_pair._ptr)
        return key_pair
