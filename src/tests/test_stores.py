import pytest
from crypto import CryptoPyProvider
from context import SignalPyContext
from stores.pre_key import VolatilePreKeyStore, VolatileSignedPreKeyStore
from stores.identity_key import VolatileIdentityKeyStore
from stores.sender_key import VolatileSenderKeyStore
from stores.session import VolatileSessionStore
from stores import VolatileProtocolStore


def test_crypto_provider():
    crypto_provider = CryptoPyProvider()
    assert crypto_provider


def test_pre_key_store():
    pre_key_store = VolatilePreKeyStore()
    assert pre_key_store


def test_signed_pre_key_store():
    signed_pre_key_store = VolatileSignedPreKeyStore()
    assert signed_pre_key_store


def test_identity_key_store():
    ctx = SignalPyContext()

    identity_key_store = VolatileIdentityKeyStore(ctx)
    assert identity_key_store


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