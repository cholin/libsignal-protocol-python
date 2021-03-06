from abc import ABC, abstractmethod
from ..cffi import ffi, GenericBinder, StructBinder, invoke
from ..keys import RatchetIdentityKeyPair


class ProtocolStore(GenericBinder, ABC):
    cdecl = 'signal_protocol_store_context **'

    def __init__(self, ctx, uri=None):
        super(ProtocolStore, self).__init__()

        self.uri = uri
        self.ctx = ctx

        invoke('signal_protocol_store_context_create', self._ptr, ctx.value)

        # add callbacks
        invoke('signal_protocol_store_context_set_session_store',
               self.value, self.get_session_store().ptr)
        invoke('signal_protocol_store_context_set_pre_key_store',
               self.value, self.get_pre_key_store().ptr)
        invoke('signal_protocol_store_context_set_sender_key_store',
               self.value, self.get_sender_key_store().ptr)
        invoke('signal_protocol_store_context_set_signed_pre_key_store',
               self.value, self.get_signed_pre_key_store().ptr)
        invoke('signal_protocol_store_context_set_identity_key_store',
               self.value, self.get_identity_key_store().ptr)

    def __del__(self):
        invoke('signal_protocol_store_context_destroy', self.value)

    @abstractmethod
    def get_session_store():
        pass

    @abstractmethod
    def get_pre_key_store():
        pass

    @abstractmethod
    def get_sender_key_store():
        pass

    @abstractmethod
    def get_signed_pre_key_store():
        pass

    @abstractmethod
    def get_identity_key_store():
        pass

    @property
    def identity(self):
        identity = RatchetIdentityKeyPair()
        invoke('signal_protocol_identity_get_key_pair', self.value,
               identity._ptr)
        return identity

    @property
    def registration_id(self):
        uint32 = ffi.new('uint32_t*')
        invoke('signal_protocol_identity_get_local_registration_id',
               self.value, uint32)
        return int(uint32[0])

    def save_identity(self, address, identity_pub_key):
        return invoke('signal_protocol_identity_save_identity', self.value,
                      address.ptr, identity_pub_key.ptr)

    def is_trusted_identity(self, address, identity_public_key):
        return invoke('signal_protocol_identity_is_trusted_identity',
                      self.value, address.ptr, identity_public_key.ptr) == 1


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


class PreKeyStore(StructBinder, ABC):
    cdecl = 'signal_protocol_pre_key_store*'

    @abstractmethod
    def load_pre_key(self, record, pre_key_id):
        pass

    @abstractmethod
    def store_pre_key(self, pre_key_id, record, record_len):
        pass

    @abstractmethod
    def contains_pre_key(self, pre_key_id):
        pass

    @abstractmethod
    def remove_pre_key(self, pre_key_id):
        pass

    @abstractmethod
    def get_all_pre_key_ids(self):
        pass


class SignedPreKeyStore(StructBinder, ABC):
    cdecl = 'signal_protocol_signed_pre_key_store*'

    @abstractmethod
    def load_signed_pre_key(self, record, signed_pre_key_id):
        pass

    @abstractmethod
    def store_signed_pre_key(self, signed_pre_key_id, record, record_len):
        pass

    @abstractmethod
    def contains_signed_pre_key(self, signed_pre_key_id):
        pass

    @abstractmethod
    def remove_signed_pre_key(self, signed_pre_key_id):
        pass

    @abstractmethod
    def get_all_signed_pre_key_ids(self):
        pass


class SenderKeyStore(StructBinder, ABC):
    cdecl = 'signal_protocol_sender_key_store*'

    @abstractmethod
    def store_sender_key(self, sender_key_name, record, record_len,
                         user_record, user_record_len):
        pass

    @abstractmethod
    def load_sender_key(self, record, user_record, sender_key_name):
        pass


class SessionStore(StructBinder, ABC):
    cdecl = 'signal_protocol_session_store*'

    @abstractmethod
    def load_session_func(self, record, user_record, address):
        pass

    @abstractmethod
    def get_sub_device_sessions_func(self, sessions, name, name_len):
        pass

    @abstractmethod
    def store_session_func(self, address, record, record_len, user_record,
                           user_record_len):
        pass

    @abstractmethod
    def contains_session_func(self, address):
        pass

    @abstractmethod
    def delete_session_func(self, address):
        pass

    @abstractmethod
    def delete_all_sessions_func(self, name, name_len):
        pass
