from ..session import SessionBuilder, SessionCipher
from ..address import Address
from ..context import SignalPyContext
from ..buffer import Buffer
from ..keys import SessionPreKey, SessionSignedPreKey, SessionPreKeyBundle
from ..cffi import lib
from ..messages import PreKeySignalMsg
from ..stores.volatile import VolatileProtocolStore
from ..stores.sqlite import SqliteProtocolStore


def test_session_decrypt():
    # alice keys
    alice_ctx = SignalPyContext()
    # alice_store = VolatileProtocolStore(alice_ctx)
    alice_store = SqliteProtocolStore(alice_ctx, ':memory:')
    alice_identity = alice_store.identity
    alice_signed_pre_key = SessionSignedPreKey.generate(alice_ctx, alice_identity, 1)
    alice_pre_key = list(SessionPreKey.generate(alice_ctx, count=1))[0]

    # bob keys
    bob_ctx = SignalPyContext()
    # bob_store = VolatileProtocolStore(bob_ctx)
    bob_store = SqliteProtocolStore(bob_ctx, ':memory:')
    bob_identity = bob_store.identity
    bob_signed_pre_key = SessionSignedPreKey.generate(bob_ctx, bob_identity, 1)
    bob_pre_key = list(SessionPreKey.generate(bob_ctx, count=1))[0]

    # save bob's keys locally to be able to retrieve private key parts
    bob_signed_pre_key_serilized = bob_signed_pre_key.serialize()
    bob_store.signed_pre_key_store.store_signed_pre_key(bob_signed_pre_key.id, bob_signed_pre_key_serilized.data, len(bob_signed_pre_key_serilized))

    bob_pre_key_serilized = bob_pre_key.serialize()
    bob_store.pre_key_store.store_pre_key(bob_pre_key.id, bob_pre_key_serilized.data, len(bob_pre_key_serilized))

    # get bob's keys (from a server) and the identity in alice own store +
    # create pre-key bundle with the rest
    alice_recipient = Address.create(b'bob', 1)
    alice_bundle_bob = SessionPreKeyBundle.create(1, 1, bob_identity.public_key, bob_signed_pre_key.signed_pub_key, bob_pre_key.public_key)
    bob_identity_serialized = bob_identity.public_key.serialize()
    alice_store.identity_key_store.save_identity(alice_recipient.ptr, bob_identity_serialized.data, len(bob_identity_serialized))

    alice_builder = SessionBuilder.create(alice_ctx, alice_store, alice_recipient)
    assert alice_builder

    alice_builder.process_pre_key_bundle(alice_bundle_bob)
    alice_session = SessionCipher.create(alice_ctx, alice_store, alice_recipient)
    assert alice_session

    # encrypt - as it is a new session, it will be a pre_key_message
    msg = Buffer.create(b'foo')
    ciphertext = alice_session.encrypt(msg)
    assert ciphertext.type == lib.CIPHERTEXT_PREKEY_TYPE
    serialized = ciphertext.serialize()

    # transmit over wire

    bob_ciphertext = PreKeySignalMsg.deserialize(bob_ctx, serialized)
    assert bob_ciphertext
    assert bob_ciphertext.version == lib.CIPHERTEXT_CURRENT_VERSION
    assert not bob_ciphertext.has_pre_key_id()
    assert bob_ciphertext.identity_pub_key == alice_identity.public_key
    assert bob_ciphertext.message

    msg = bob_ciphertext.message
    assert msg.counter == 0
    assert msg.version == 3
    assert msg.sender_ratchet_public_key

    bob_recipient = Address.create(b'alice', 1)
    identity_serialized = bob_ciphertext.identity_pub_key.serialize()
    bob_store.identity_key_store.save_identity(bob_recipient.ptr, identity_serialized.data, len(identity_serialized))

    bob_session = SessionCipher.create(bob_ctx, bob_store, bob_recipient)
    plaintext = bob_session.decrypt_pre_key_signal_msg(bob_ciphertext)
    assert plaintext.bin() == b'foo'
