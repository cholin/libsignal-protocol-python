from abc import ABC, abstractmethod
from cffi import ffi, lib, GenericBinder
from keys import RatchetIdentityKeyPair
from stores.pre_key import VolatilePreKeyStore, VolatileSignedPreKeyStore
from stores.identity_key import VolatileIdentityKeyStore
from stores.sender_key import VolatileSenderKeyStore
from stores.session import VolatileSessionStore


class ProtocolStore(GenericBinder, ABC):
    cdecl = 'signal_protocol_store_context **'

    def __init__(self, ctx):
        super(ProtocolStore, self).__init__()

        self.ctx = ctx

        lib.signal_protocol_store_context_create(self._ptr, ctx.value)

        # add callbacks
        lib.signal_protocol_store_context_set_session_store(
                self.value, self.get_session_store().ptr)
        lib.signal_protocol_store_context_set_pre_key_store(
                self.value, self.get_pre_key_store().ptr)
        lib.signal_protocol_store_context_set_sender_key_store(
                self.value, self.get_sender_key_store().ptr)
        lib.signal_protocol_store_context_set_signed_pre_key_store(
                self.value, self.get_signed_pre_key_store().ptr)
        lib.signal_protocol_store_context_set_identity_key_store(
                self.value, self.get_identity_key_store().ptr)

    def __del__(self):
        lib.signal_protocol_store_context_destroy(self.value)

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
        lib.signal_protocol_identity_get_key_pair(self.value, identity._ptr)
        return identity

    @property
    def registration_id(self):
        uint32 = ffi.new('uint32_t*')
        lib.signal_protocol_identity_get_local_registration_id(self.value, uint32)
        return int(uint32[0])

    def save_identity(self, address, identity_pub_key):
        return lib.signal_protocol_identity_save_identity(self.value, address.ptr, identity_pub_key.ptr)

    def is_trusted_identity(self, address, identity_public_key):
        return lib.signal_protocol_identity_is_trusted_identity(self.value,
            address.ptr, identity_public_key.ptr) == 1


# int signal_protocol_session_load_session(signal_protocol_store_context *context, session_record **record, const signal_protocol_address *address);
# int signal_protocol_session_get_sub_device_sessions(signal_protocol_store_context *context, signal_int_list **sessions, const char *name, size_t name_len);
# int signal_protocol_session_store_session(signal_protocol_store_context *context, const signal_protocol_address *address, session_record *record);
# int signal_protocol_session_contains_session(signal_protocol_store_context *context, const signal_protocol_address *address);
# int signal_protocol_session_delete_session(signal_protocol_store_context *context, const signal_protocol_address *address);
# int signal_protocol_session_delete_all_sessions(signal_protocol_store_context *context, const char *name, size_t name_len);
# int signal_protocol_pre_key_load_key(signal_protocol_store_context *context, session_pre_key **pre_key, uint32_t pre_key_id);
# int signal_protocol_pre_key_store_key(signal_protocol_store_context *context, session_pre_key *pre_key);
# int signal_protocol_pre_key_contains_key(signal_protocol_store_context *context, uint32_t pre_key_id);
# int signal_protocol_pre_key_remove_key(signal_protocol_store_context *context, uint32_t pre_key_id);
# int signal_protocol_signed_pre_key_load_key(signal_protocol_store_context *context, session_signed_pre_key **pre_key, uint32_t signed_pre_key_id);
# int signal_protocol_signed_pre_key_store_key(signal_protocol_store_context *context, session_signed_pre_key *pre_key);
# int signal_protocol_signed_pre_key_contains_key(signal_protocol_store_context *context, uint32_t signed_pre_key_id);
# int signal_protocol_signed_pre_key_remove_key(signal_protocol_store_context *context, uint32_t signed_pre_key_id);
# int signal_protocol_identity_get_key_pair(signal_protocol_store_context *context, ratchet_identity_key_pair **key_pair);
# int signal_protocol_identity_get_local_registration_id(signal_protocol_store_context *context, uint32_t *registration_id);
# int signal_protocol_identity_save_identity(signal_protocol_store_context *context, const signal_protocol_address *address, ec_public_key *identity_key);
# int signal_protocol_identity_is_trusted_identity(signal_protocol_store_context *context, const signal_protocol_address *address, ec_public_key *identity_key);
# int signal_protocol_sender_key_store_key(signal_protocol_store_context *context, const signal_protocol_sender_key_name *sender_key_name, sender_key_record *record);
# int signal_protocol_sender_key_load_key(signal_protocol_store_context *context, sender_key_record **record, const signal_protocol_sender_key_name *sender_key_name);



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