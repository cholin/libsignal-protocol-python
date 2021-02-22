from ..address import Address
from ..protocol import SignalProtocol
from ..cffi import lib


def test_protocol():
    # create identity for bob (with keys)
    bob = SignalProtocol(b'bob')
    bob_signed_pre_pub_key = bob.generate_signed_pre_key()
    bob_pre_pub_keys = list(bob.generate_pre_keys())

    # publish bob's public keys so that Alice can retrieve them

    # create identity for alice
    alice = SignalProtocol(b'alice')

    # alice -> bob
    #   retrieve public key of Bob
    alice_session_bob = alice.session(b'bob', 1)
    if not alice_session_bob.initialized:
        bob_pub_keys = (bob.registration_id,
                        bob.identity.public_key, bob_signed_pre_pub_key,
                        bob_pre_pub_keys[0])
        alice_session_bob.process(*bob_pub_keys)

    msg = b'foo'
    ciphertext = alice_session_bob.encrypt(msg)

    assert ciphertext.type == lib.CIPHERTEXT_PREKEY_TYPE

    serialized = (lib.CIPHERTEXT_PREKEY_TYPE, ciphertext.serialize())

    # transmit serialized over wire

    plaintext = bob.session(b'alice', 1).decrypt(*serialized)
    assert plaintext.bin() == msg
    print(plaintext.bin(), msg)

    # bob -> alice
    bob_session_alice = bob.session(b'alice', 1)
    ciphertext = bob_session_alice.encrypt(msg)

    assert ciphertext.type == lib.CIPHERTEXT_SIGNAL_TYPE

    serialized = (lib.CIPHERTEXT_SIGNAL_TYPE, ciphertext.serialize())

    # transmit serialized over wire

    plaintext = alice.session(b'bob', 1).decrypt(*serialized)
    assert plaintext.bin() == msg
    print(plaintext.bin(), msg)