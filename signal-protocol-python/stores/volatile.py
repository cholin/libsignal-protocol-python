from cffi import ffi, lib, invoke
from keys import RatchetIdentityKeyPair
from buffer import Buffer
from copy import copy
from . import ProtocolStore, IdentityKeyStore, PreKeyStore, SignedPreKeyStore,\
              SenderKeyStore, SessionStore


class VolatileProtocolStore(ProtocolStore):

    def get_session_store(self):
        self.session_store = VolatileSessionStore()
        return self.session_store

    def get_pre_key_store(self):
        self.pre_key_store = VolatilePreKeyStore()
        return self.pre_key_store

    def get_sender_key_store(self):
        self.sender_key_store = VolatileSenderKeyStore()
        return self.sender_key_store

    def get_signed_pre_key_store(self):
        self.signed_pre_key_store = VolatileSignedPreKeyStore()
        return self.signed_pre_key_store

    def get_identity_key_store(self):
        self.identity_key_store = VolatileIdentityKeyStore(self.ctx)
        return self.identity_key_store


class VolatileIdentityKeyStore(IdentityKeyStore):
    def __init__(self, ctx):
        super(IdentityKeyStore, self).__init__()

        self.identity_key_pair = RatchetIdentityKeyPair.generate(ctx)

        self.local_registration_id = ffi.new('uint32_t*')
        invoke('signal_protocol_key_helper_generate_registration_id',
               self.local_registration_id, 0, ctx.value)

        self.trustedKeys = {}

    def get_identity_key_pair(self, public_data, private_data):
        invoke('ec_public_key_serialize', public_data,
               self.identity_key_pair.public_key.ptr)
        invoke('ec_private_key_serialize', private_data,
               self.identity_key_pair.private_key.ptr)
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
        self.trustedKeys[key] = Buffer.create(key_data, key_len)
        return 0

    def is_trusted_identity(self, address, key_data, key_len):
        key = self.get_key_for(address)
        data = Buffer.create(key_data, key_len)
        try:
            if data == self.trustedKeys[key]:
                return 1
        except KeyError:
            self.save_identity(address, key_data, key_len)
            return 1
        return 0


class VolatilePreKeyStore(PreKeyStore):
    def __init__(self):
        super(VolatilePreKeyStore, self).__init__()
        self._keys = {}

    def load_pre_key(self, record, pre_key_id):
        if pre_key_id not in self._keys:
            return lib.SG_ERR_INVALID_KEY_ID
        record[0] = copy(self._keys[pre_key_id]).release()
        return lib.SG_SUCCESS

    def store_pre_key(self, pre_key_id, record, record_len):
        self._keys[pre_key_id] = Buffer.create(record, record_len)
        return 1

    def contains_pre_key(self, pre_key_id):
        if pre_key_id in self._keys:
            return 1
        return 0

    def remove_pre_key(self, pre_key_id):
        if pre_key_id not in self._keys:
            return 1
        del self._keys[pre_key_id]
        return 0


class VolatileSignedPreKeyStore(SignedPreKeyStore, VolatilePreKeyStore):

    def load_signed_pre_key(self, record, signed_pre_key_id):
        return self.load_pre_key(record, -signed_pre_key_id)

    def store_signed_pre_key(self, signed_pre_key_id, record, record_len):
        return self.store_pre_key(-signed_pre_key_id, record, record_len)

    def contains_signed_pre_key(self, signed_pre_key_id):
        return self.contains_pre_key(-signed_pre_key_id)

    def remove_signed_pre_key(self, signed_pre_key_id):
        return self.remove_pre_key(-signed_pre_key_id)


class VolatileSenderKeyStore(SenderKeyStore):

    def store_sender_key(self, sender_key_name, record, record_len,
                         user_record, user_record_len):
        raise NotImplementedError

    def load_sender_key(self, record, user_record, sender_key_name):
        raise NotImplementedError


class VolatileSessionStore(SessionStore):

    def __init__(self):
        super(VolatileSessionStore, self).__init__()
        self.sessions = {}

    @staticmethod
    def join_address(address):
        name = ffi.buffer(address.name, address.name_len)[:]
        return name + b'_' + bytes([address.device_id])

    def load_session_func(self, record, user_record, address):
        key = self.join_address(address)
        if key not in self.sessions:
            return 0

        record[0] = copy(self.sessions[key]).release()

        return 1

    def get_sub_device_sessions_func(self, sessions, name, name_len):
        raise NotImplementedError

    def store_session_func(self, address, record, record_len, user_record,
                           user_record_len):
        key = self.join_address(address)
        self.sessions[key] = Buffer.create(record, record_len)
        return 0

    def contains_session_func(self, address):
        key = self.join_address(address)
        if key in self.sessions:
            return 1
        return 0

    def delete_session_func(self, address):
        key = self.join_address(address)
        if key not in self.sessions:
            return 0

        del self.sessions[key]
        return 1

    def delete_all_sessions_func(self, name, name_len):
        self.sessions.clear
        return 0
