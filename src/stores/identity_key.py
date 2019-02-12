from abc import ABC, abstractmethod
from cffi import ffi, lib, StructBinder
from keys import RatchetIdentityKeyPair
from buffer import Buffer


class IdentityKeyStore(StructBinder, ABC):
    cdecl = 'signal_protocol_identity_key_store*'

    @abstractmethod
    def get_identity_key_pair(self, public_data, private_data):
        pass

    @abstractmethod
    def get_local_registration_id(self, registration_id):
        pass

    @abstractmethod
    def save_identity(self, address, key_data, key_len):
        pass

    @abstractmethod
    def is_trusted_identity(self, address, key_data, key_len):
        pass


class VolatileIdentityKeyStore(IdentityKeyStore):
    def __init__(self, ctx):
        super(IdentityKeyStore, self).__init__()

        self.identity_key_pair = RatchetIdentityKeyPair.generate(ctx)
        
        self.local_registration_id = ffi.new('uint32_t*')
        lib.signal_protocol_key_helper_generate_registration_id(self.local_registration_id, 0, ctx.value)

        self.trustedKeys = {}

    def get_identity_key_pair(self, public_data, private_data):
        lib.ec_public_key_serialize(public_data, self.identity_key_pair.public_key.ptr)
        lib.ec_private_key_serialize(private_data, self.identity_key_pair.private_key.ptr)
        return 0

    def get_local_registration_id(self, registration_id):
        registration_id[0] = self.local_registration_id[0]
        return 0

    @staticmethod
    def get_key_for(address):
        # TODO: Use Address python class
        name = ffi.buffer(address.name, address.name_len)[:]
        return b'%s-%d' % (name, address.device_id)

    def save_identity(self, address, key_data, key_len):
        key = self.get_key_for(address)
        print("save identity", key)
        self.trustedKeys[key] = Buffer.create(key_data, key_len)
        return 0

    def is_trusted_identity(self, address, key_data, key_len):
        key = self.get_key_for(address)
        print('is_trusted_identity', key)
        data = Buffer.create(key_data, key_len)
        try:
            if data == self.trustedKeys[key]:
                print("yeea")
                return 1
        except KeyError:
            print("yeea inserted")
            self.save_identity(address, key_data, key_len)
            return 1
        print("no")
        return 0
