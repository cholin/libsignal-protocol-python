from ..context import SignalPyContext
from ..buffer import Buffer
from ..keys import RatchetIdentityKeyPair
from ..curve import EcKeyPair, EcPublicKey, EcPrivateKey
from .data import EC_PUBLIC_KEY_HEX, EC_PRIVATE_KEY_HEX, \
                  RATCHET_IDENTITY_KEY_PAIR_HEX


def test_ratchet_identity_key_pair_create():
    ctx = SignalPyContext()

    key_pair = EcKeyPair.generate(ctx)
    identity_key_pair = RatchetIdentityKeyPair.create(key_pair)
    assert identity_key_pair
    assert identity_key_pair.public_key == key_pair.public_key
    assert identity_key_pair.private_key == key_pair.private_key


def test_ratchtet_identity_key_pair_generate():
    ctx = SignalPyContext()

    identity_key_pair = RatchetIdentityKeyPair.generate(ctx)
    assert identity_key_pair

    created = RatchetIdentityKeyPair.create(identity_key_pair.key_pair)
    assert created == identity_key_pair


def test_ratchet_identity_key_pair_serializer():
    ctx = SignalPyContext()

    pub_key_serialized = Buffer.fromhex(EC_PUBLIC_KEY_HEX)
    pub_key = EcPublicKey.decode_point(ctx, pub_key_serialized)
    assert pub_key

    priv_key_serialized = Buffer.fromhex(EC_PRIVATE_KEY_HEX)
    priv_key = EcPrivateKey.decode_point(ctx, priv_key_serialized)
    assert priv_key

    identity_key_pair_serialized = Buffer.fromhex(
        RATCHET_IDENTITY_KEY_PAIR_HEX)
    identity_key_pair = RatchetIdentityKeyPair.deserialize(
        ctx, identity_key_pair_serialized)
    assert identity_key_pair
    assert identity_key_pair.public_key == pub_key
    assert identity_key_pair.private_key == priv_key

    assert identity_key_pair.serialize() == identity_key_pair_serialized
    assert pub_key.serialize() == pub_key_serialized
    assert priv_key.serialize() == priv_key_serialized
