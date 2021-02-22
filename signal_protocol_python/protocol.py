from base64 import b64encode
from importlib import import_module
from .cffi import ffi, invoke
from .address import Address
from .keys import SessionSignedPreKey, SessionPreKey
from .stores.volatile import VolatileProtocolStore
from .stores.sqlite import SqliteProtocolStore
from .context import SignalPyContext
from .session import Session


class SignalProtocol:
    def __init__(self, name, uri='volatile:/'):
        self.address = Address.create(name, 1)
        self.ctx = SignalPyContext()

        # instantiate dynamically by uri prefix
        backend, uri = uri.split(':/', 1)
        pkg ='signal_protocol_python'
        module = import_module('.stores.'+backend, package=pkg)
        cls_name = '{}ProtocolStore'.format(backend.capitalize())
        cls = getattr(module, cls_name)

        self.store = cls(self.ctx, uri)

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

    @property
    def signed_pre_key_ids(self):
        store = self.store.get_signed_pre_key_store()
        return store.get_all_signed_pre_key_ids()

    @property
    def signed_pre_keys(self):
        return [self.load_signed_pre_key(i) for i in self.signed_pre_key_ids]

    @property
    def pre_key_ids(self):
        store = self.store.get_pre_key_store()
        return store.get_all_pre_key_ids()

    @property
    def pre_keys(self):
        return [self.load_pre_key(i) for i in self.pre_key_ids]

    def load_pre_key(self, pre_key_id):
        pre_key = SessionPreKey()
        invoke('signal_protocol_pre_key_load_key', self.store.value,
               pre_key._ptr, pre_key_id)
        return pre_key

    def load_signed_pre_key(self, signed_pre_key_id):
        signed_pre_key = SessionSignedPreKey()
        invoke('signal_protocol_signed_pre_key_load_key', self.store.value,
               signed_pre_key._ptr, signed_pre_key_id)
        return signed_pre_key

    def generate_signed_pre_key(self):
        next_id = max(self.signed_pre_key_ids, default=0)+1
        signed_pre_key = SessionSignedPreKey.generate(self.ctx, self.identity,
                                                      next_id)
        invoke('signal_protocol_signed_pre_key_store_key', self.store.value,
               signed_pre_key.ptr)
        return signed_pre_key.signed_pub_key

    def generate_pre_keys(self):
        next_id = max(self.pre_key_ids, default=0)+1
        pre_keys = SessionPreKey.generate(self.ctx, start=next_id)
        for pre_key in pre_keys:
            invoke('signal_protocol_pre_key_store_key', self.store.value,
                   pre_key.ptr)
            yield pre_key.public_key

    def session(self, recipient, device_id):
        address = Address.create(recipient, device_id)
        return Session(self.ctx, self.store, address)

    def get_public_keys(self):
        keys = {}

        keys['identityKey'] = self.identity.public_key.serialize().b64().decode()

        signed_pre_key = self.signed_pre_keys[-1]
        keys['signedPreKey'] = {
            'keyId': signed_pre_key.id,
            'publicKey': signed_pre_key.signed_pub_key.serialize().b64().decode(),
            'signature': signed_pre_key.signature.b64().decode()
        }

        keys['preKeys'] = [
            {
                'keyId': pre_key.id,
                'publicKey': pre_key.public_key.serialize().b64().decode(),
            }
            for pre_key in self.pre_keys
        ]

        # „This is just to make the server happy (v2 clients should choke on publicKey)“
        # see https://github.com/signalapp/Signal-Desktop/blob/a173a9b33ff8dccbe02b9ad2d5e268ca3b036563/ts/textsecure/WebAPI.ts#L1428
        keys['lastResortKey'] = {
            'keyId': 0x7fffffff,
            'publicKey': b64encode(b'42').decode()
        }

        return keys

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

