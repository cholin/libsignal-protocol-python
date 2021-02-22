import gc
from copy import copy
from ..address import Address


def teardown_method(self, method):
    gc.collect()


def test_address_empty():
    address = Address()
    assert len(address.name) == 0
    assert address.device_id == 0
    assert Address() == Address()


def test_address_setters():
    address = Address()
    address.name = b'foo'
    assert address.name == b'foo'

    address.device_id = 99
    assert address.device_id == 99


def test_address_create():
    address = Address.create(b'foo', 1)
    assert address.name == b'foo'
    assert address.device_id == 1


def test_address_copy():
    address = Address.create(b'foo', 1)
    copied = copy(address)
    assert copied.name == b'foo'
    assert copied.device_id == 1
    assert address == copied
