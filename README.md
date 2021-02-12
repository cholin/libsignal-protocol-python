signal-protocol-python
======================

Python 3 bindings for *libsignal-protocol-c*. The actual c code is integrated
using the *C Foreign Function Interface for Python* package.

DISCLAMER: Incomplete and untrusthworthy python bindings for
libsignal-protocol-c. These bindings were used for academic research purposes
and should not be used in real world cryptographic applications. For a more
mature alternative you may want to consider https://github.com/tgalal/python-axolotl.


Get Started
-----------

### Get Source
```
> git clone git@github.com:cholin/libsignal-protocol-python.git
> git submodule update --init --recursive
```

### Build libsignal-protocol-c as library
```
> cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POSITION_INDEPENDENT_CODE=ON libs/libsignal-protocol-c -Bbuild
> make -C build
```

### Create environment and install dependencies
```
> python -m venv env
> . env/bin/activate
> pip install -r requirements.txt
```

### Build CFFI
```
> python src/cffi/build.py
```

Example
-------

Alice and Bob example code (see *tests/test_protocol.py*)

```python
# create identity for bob (with keys)
bob = SignalProtocol(b'bob')
bob_signed_pre_pub_key = bob.generate_signed_pre_key()
bob_pre_pub_keys = list(bob.generate_pre_keys())

# publish bob's public keys so that Alice can retrieve them

# create identity for alice
alice = SignalProtocol(b'alice')

# alice -> bob (Alice needs Bob's public key parts)
alice_session_bob = alice.session(Address.create(b'bob', 1))
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

plaintext = bob.session(Address.create(b'alice', 1)).decrypt(*serialized)
assert plaintext.bin() == msg
print(plaintext.bin(), msg)
```

Tests
-----

Tests are written with pytest and can be started as follows:

```
pytest -s
```
