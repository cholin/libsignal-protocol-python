import pytest
from ..cffi import ffi
from ..crypto import CryptoPyProvider
from ..context import SignalPyContext
from ..buffer import Buffer
from ..address import Address
from ..curve import EcPublicKey, EcPrivateKey, EcKeyPair
from ..keys import RatchetIdentityKeyPair, SessionPreKey, SessionSignedPreKey
from ..stores.volatile import VolatileProtocolStore, VolatilePreKeyStore,    \
                              VolatileIdentityKeyStore, VolatileSessionStore,\
                              VolatileSenderKeyStore, VolatileSignedPreKeyStore
from ..stores.sqlite import SqliteIdentityKeyStore, SqlitePreKeyStore, \
                            SqliteSignedPreKeyStore, SqliteSessionStore


def test_crypto_provider():
    crypto_provider = CryptoPyProvider()
    assert crypto_provider


def test_sender_key_store():
    sender_key_store = VolatileSenderKeyStore()
    assert sender_key_store


def test_session_store():
    session_store = VolatileSessionStore()
    assert session_store


def test_protocol_store():
    ctx = SignalPyContext()
    protocol_store = VolatileProtocolStore(ctx)
    assert protocol_store


def test_protocol_store_non_copyable():
    ctx = SignalPyContext()
    protocol_store = VolatileProtocolStore(ctx)
    assert protocol_store
    from copy import copy
    with pytest.raises(RuntimeError):
        assert copy(protocol_store)


def test_identity_key_store_identity_key_pair():
    ctx = SignalPyContext()

    stores = [
        VolatileIdentityKeyStore(ctx),
        SqliteIdentityKeyStore(ctx, ':memory:')
    ]
    for store in stores:
        assert store

        public_point = Buffer()
        private_point = Buffer()
        store.get_identity_key_pair(public_point.ptr, private_point.ptr)

        public_key = EcPublicKey.decode_point(ctx, public_point)
        assert public_key

        private_key = EcPrivateKey.decode_point(ctx, private_point)
        assert private_key

        key_pair = EcKeyPair.create(public_key, private_key)
        assert key_pair

        identity = RatchetIdentityKeyPair.create(key_pair)
        assert identity
        assert identity.public_key == public_key
        assert identity.private_key == private_key


def test_identity_key_store_identity_registration_id():
    ctx = SignalPyContext()

    stores = [
        VolatileIdentityKeyStore(ctx),
        SqliteIdentityKeyStore(ctx, ':memory:')
    ]
    for store in stores:
        assert store

        # get reg_id
        uint32_ptr_a = ffi.new('uint32_t*')
        store.get_local_registration_id(uint32_ptr_a)
        assert uint32_ptr_a[0]

        # check if we get the same id for multiple calls
        uint32_ptr_b = ffi.new('uint32_t*')
        store.get_local_registration_id(uint32_ptr_b)
        assert uint32_ptr_b[0]
        assert uint32_ptr_a[0] == uint32_ptr_b[0]


def test_identity_key_store_save_and_trust():
    ctx = SignalPyContext()

    stores = [
        VolatileIdentityKeyStore(ctx),
        SqliteIdentityKeyStore(ctx, ':memory:')
    ]
    for store in stores:
        assert store

        # generate random public key for identity foo-1
        address = Address.create(b'foo', 1)
        pub_key = EcKeyPair.generate(ctx).public_key
        serialized = pub_key.serialize()

        # new identiy should not yet in our store -> untrusted
        args = (address.ptr, serialized.data, len(serialized))
        result = store.is_trusted_identity(*args)
        assert result == 0

        # save identity in store
        result = store.save_identity(*args)
        assert result == 0

        # check if trusted now
        result = store.is_trusted_identity(*args)
        assert result == 1


def test_pre_key_store():
    ctx = SignalPyContext()

    stores = [
        VolatilePreKeyStore(),
        SqlitePreKeyStore(':memory:')
    ]
    for store in stores:
        pre_keys = list(SessionPreKey.generate(ctx))

        # store+contains
        for pre_key in pre_keys:
            serialized = pre_key.serialize()
            assert store.contains_pre_key(pre_key.id) == 0
            store.store_pre_key(pre_key.id, serialized.data, len(serialized))
            assert store.contains_pre_key(pre_key.id) == 1

        # loading key
        for pre_key in pre_keys:
            buf = Buffer()
            store.load_pre_key(buf.ptr, pre_key.id)
            deserialized = SessionPreKey.deserialize(ctx, buf)
            assert pre_key.id == deserialized.id
            assert pre_key.public_key == deserialized.public_key

        # remove key
        for pre_key in pre_keys:
            assert store.contains_pre_key(pre_key.id) == 1
            store.remove_pre_key(pre_key.id)
            assert store.contains_pre_key(pre_key.id) == 0


def test_signed_pre_key_store():
    ctx = SignalPyContext()

    stores = [
        VolatileSignedPreKeyStore(),
        SqliteSignedPreKeyStore(':memory:')
    ]
    for store in stores:
        identity = RatchetIdentityKeyPair.generate(ctx)
        signed_pre_key = SessionSignedPreKey.generate(ctx, identity, 1)

        # store+contains
        serialized = signed_pre_key.serialize()
        assert store.contains_signed_pre_key(signed_pre_key.id) == 0
        store.store_signed_pre_key(signed_pre_key.id,
                                   serialized.data, len(serialized))
        assert store.contains_signed_pre_key(signed_pre_key.id) == 1

        # loading key
        buf = Buffer()
        store.load_signed_pre_key(buf.ptr, signed_pre_key.id)
        deserialized = SessionSignedPreKey.deserialize(ctx, buf)
        assert signed_pre_key.id == deserialized.id
        assert signed_pre_key.signed_pub_key == deserialized.signed_pub_key
        assert signed_pre_key.signature == deserialized.signature

        # remove key
        assert store.contains_signed_pre_key(signed_pre_key.id) == 1
        store.remove_signed_pre_key(signed_pre_key.id)
        assert store.contains_signed_pre_key(signed_pre_key.id) == 0


def test_session_store():
    ctx = SignalPyContext()

    stores = [
        VolatileSessionStore(),
        SqliteSessionStore(':memory:')
    ]
    for store in stores:
        pass
        #session record
        #store.store_session_func()