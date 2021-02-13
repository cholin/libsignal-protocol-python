from context import SignalPyContext
from buffer import Buffer
from curve import EcKeyPair, EcPrivateKey, EcPublicKey
import pytest
import gc
import errors


def teardown_method(self, method):
    gc.collect()


def test_ec_key_pair_generate():
    ctx = SignalPyContext()
    key_pair = EcKeyPair.generate(ctx)
    assert key_pair
    assert key_pair.public_key

    priv_key = key_pair.private_key
    assert key_pair.private_key

    pub_key = EcPublicKey.generate(priv_key)
    assert pub_key
    assert key_pair.public_key == pub_key


def test_ec_private_key():
    ctx = SignalPyContext()
    priv_key = EcPrivateKey.generate(ctx)
    assert priv_key

    serialized = priv_key.serialize()
    assert serialized
    assert len(serialized) > 0

    decoded = EcPrivateKey.decode_point(ctx, serialized)
    assert decoded
    assert decoded == priv_key


def test_ec_pub_key_serialize():
    ctx = SignalPyContext()

    key_pair = EcKeyPair.generate(ctx)
    assert key_pair

    pub_key = key_pair.public_key
    assert pub_key

    data = pub_key.serialize()
    assert data
    assert len(data) > 0

    decoded = EcPublicKey.decode_point(ctx, data)
    assert decoded
    assert pub_key == decoded


def test_ec_signatures():
    ctx = SignalPyContext()

    data = Buffer.create(b'123')
    key_pair = EcKeyPair.generate(ctx)
    pub_key = key_pair.public_key
    priv_key = key_pair.private_key

    signature = priv_key.sign(ctx, data)
    assert len(signature) == 64
    assert pub_key.verify(data, signature)

    # wrong data
    invalid = Buffer.create(b'wrong')
    assert not pub_key.verify(invalid, signature)

    # invalid signature
    with pytest.raises(errors.InvalidArgument):
        pub_key.verify(data, invalid)


def test_ec_vrf_signatures():
    ctx = SignalPyContext()

    data = Buffer.create(b'123')
    key_pair = EcKeyPair.generate(ctx)
    pub_key = key_pair.public_key
    priv_key = key_pair.private_key

    signature = priv_key.sign_vrf(ctx, data)
    assert len(signature) == 96

    vrf_output = pub_key.verify_vrf(ctx, data, signature)
    assert len(vrf_output) == 32

    # wrong data
    invalid = Buffer.create(b'wrong')
    with pytest.raises(errors.VrfSignatureVerificationError):
        pub_key.verify_vrf(ctx, invalid, signature)

    # invalid signature
    with pytest.raises(errors.VrfSignatureVerificationError):
        pub_key.verify_vrf(ctx, data, invalid)
