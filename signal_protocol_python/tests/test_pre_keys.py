from datetime import datetime, timedelta
from ..context import SignalPyContext
from ..buffer import Buffer
from ..keys import RatchetIdentityKeyPair, SessionPreKey, SessionSignedPreKey,\
                   SessionPreKeyBundle
from ..curve import EcKeyPair, EcPublicKey, EcPrivateKey
from .data import EC_PUBLIC_KEY_HEX, EC_PRIVATE_KEY_HEX, \
                  RATCHET_IDENTITY_KEY_PAIR_HEX


def test_session_pre_key_generate():
    ctx = SignalPyContext()

    pre_keys = list(SessionPreKey.generate(ctx, 1, 20))
    assert len(pre_keys) == 20

    for i, pre_key in enumerate(pre_keys, 1):
        assert pre_key.id == i
        assert pre_key.key_pair


def test_session_pre_key_create():
    ctx = SignalPyContext()

    pub_key_serialized = Buffer.fromhex(EC_PUBLIC_KEY_HEX)
    pub_key = EcPublicKey.decode_point(ctx, pub_key_serialized)
    assert pub_key

    priv_key_serialized = Buffer.fromhex(EC_PRIVATE_KEY_HEX)
    priv_key = EcPrivateKey.decode_point(ctx, priv_key_serialized)
    assert priv_key

    key_pair = EcKeyPair.create(pub_key, priv_key)
    pre_key = SessionPreKey.create(1, key_pair)
    assert pre_key.id == 1
    assert pre_key.key_pair == key_pair


def test_signed_session_pre_key_generate():
    ctx = SignalPyContext()

    identity_key_pair_serialized = Buffer.fromhex(
        RATCHET_IDENTITY_KEY_PAIR_HEX)
    identity_key_pair = RatchetIdentityKeyPair.deserialize(
        ctx, identity_key_pair_serialized)

    signed_pre_key = SessionSignedPreKey.generate(ctx, identity_key_pair,
                                                  1)
    assert signed_pre_key
    assert signed_pre_key.key_pair
    assert signed_pre_key.id == 1

    diff = datetime.now() - signed_pre_key.timestamp
    assert diff < timedelta(seconds=10)

    # check signature for serialized pub prekey with identity pub key
    pub_key = identity_key_pair.public_key
    content = signed_pre_key.key_pair.public_key.serialize()
    signature = signed_pre_key.signature
    assert pub_key.verify(content, signature)


def test_signed_session_pre_key_create():
    ctx = SignalPyContext()
    pub_key_serialized = Buffer.fromb64(b'BcZ4Qg77/QcIA3uWQ/tLtpr8jq2J+4HEeqnNNN0YTNoh')
    pub_key = EcPublicKey.decode_point(ctx, pub_key_serialized)

    priv_key_serialized = Buffer.fromb64(b'sM6oq+0tEXAckdbf3xwpKM9FN6zJt/o4P5mQ/gyAH1k=')
    priv_key = EcPrivateKey.decode_point(ctx, priv_key_serialized)

    key_pair = EcKeyPair.create(pub_key, priv_key)
    timestamp = datetime.fromisoformat('2021-01-31T22:53:15')
    signature = Buffer.fromb64(b'ariOjPePA6sgNVKzq803Z8fOjSpgZ4NSw+92E7GTc0bLwfjnSr1OpPle5ahTVlnifQQz5s+vJdIYtA805EGFhA==')

    EcKeyPair.create(pub_key, priv_key)
    created = SessionSignedPreKey.create(1, timestamp, key_pair, signature)
    assert created
    assert created.timestamp == timestamp
    assert created.key_pair == key_pair
    assert created.signature == signature


def test_pub_key_bundle():
    ctx = SignalPyContext()

    registration_id = 1
    device_id = 1
    identity_key_pair = EcKeyPair.generate(ctx, key_id=1)
    pub_pre_key = EcKeyPair.generate(ctx, key_id=1).public_key
    signed_pre_key_pair = EcKeyPair.generate(ctx, key_id=1)
    signed_pub_pre_key = signed_pre_key_pair.public_key
    signed_pub_pre_key.signature = identity_key_pair.private_key.sign(ctx,
            signed_pub_pre_key.serialize())

    bundle = SessionPreKeyBundle.create(registration_id, device_id,
                                        identity_key_pair.public_key,
                                        signed_pub_pre_key,
                                        pub_pre_key)
    assert bundle
    assert bundle.registration_id == 1
    assert bundle.device_id == 1
    assert bundle.pub_pre_key == pub_pre_key
    assert bundle.signed_pub_pre_key == signed_pub_pre_key
    assert bundle.signed_pub_pre_key.signature == signed_pub_pre_key.signature
    assert bundle.pub_identity_key == identity_key_pair.public_key
    assert bundle.pub_identity_key.verify(bundle.signed_pub_pre_key.serialize(),
                                          bundle.signed_pub_pre_key.signature)

