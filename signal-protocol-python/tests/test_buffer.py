import gc
from copy import copy
from buffer import Buffer


def teardown_method(self, method):
    gc.collect()


def test_buffer_empty():
    assert len(Buffer()) == 0
    assert Buffer() == Buffer()


def test_buffer_create():
    content = b'123'
    buf = Buffer.create(content)
    assert len(buf) == len(content)
    assert buf.bin() == content


def test_buffer_append():
    buf = Buffer.create(b'123')
    buf.append(b'4', 1)
    assert len(buf) == 4
    assert buf.bin() == b'1234'


def test_buffer_bin():
    # bin does not own/free/alter internal buffer
    buf = Buffer.create(b'123')
    data = buf.bin()
    del data
    gc.collect()
    assert len(buf) == 3
    assert buf.bin() == b'123'


def test_buffer_hex():
    content = b'123'
    buf = Buffer.create(content)
    assert buf.hex() == '313233'
    assert buf == Buffer.fromhex(buf.hex())


def test_buffer_64():
    content = b'123'
    buf = Buffer.create(content)
    assert buf.b64() == b'MTIz'
    assert buf == Buffer.fromb64(buf.b64())


def test_buffer_copy():
    content = b'123'
    buf = Buffer.create(content)
    assert buf == copy(buf)
