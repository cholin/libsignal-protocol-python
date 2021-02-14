
from cffi import ffi, invoke
from address import Address
from keys import SessionSignedPreKey, SessionPreKey
from stores.volatile import VolatileProtocolStore
from context import SignalPyContext
from session import Session


class SignalProtocol:
    def __init__(self, name):
        self.address = Address.create(name, 1)
        self.ctx = SignalPyContext()
        self.store = VolatileProtocolStore(self.ctx)

    @property
    def device_id(self):
        return self.address.device_id

    @property
    def registration_id(self):
        uint32 = ffi.new('uint32_t*')
        invoke('signal_protocol_identity_get_local_registration_id', 
               self.store.value, uint32)
        return int(uint32[0])

    @property
    def identity(self):
        return self.store.identity

    def generate_signed_pre_key(self):
        signed_pre_key = SessionSignedPreKey.generate(self.ctx, self.identity,
                                                      1)
        invoke('signal_protocol_signed_pre_key_store_key', self.store.value,
               signed_pre_key.ptr)
        return signed_pre_key.signed_pub_key

    def generate_pre_keys(self):
        pre_keys = SessionPreKey.generate(self.ctx)
        for pre_key in pre_keys:
            invoke('signal_protocol_pre_key_store_key', self.store.value,
                   pre_key.ptr)
            yield pre_key.public_key

    def session(self, recipient, device_id):
        address = Address.create(recipient, device_id)
        return Session(self.ctx, self.store, address)