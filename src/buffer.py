from cffi import ffi, lib, Pointer
from base64 import b64encode, b64decode


class Buffer(Pointer):
    cdecl = 'signal_buffer**'

    def __del__(self):
        if self.ptr:
            lib.signal_buffer_bzero_free(self.value)

    def __copy__(self):
        copied = Buffer()
        if self.ptr:
            copied._ptr[0] = lib.signal_buffer_copy(self.value)
        return copied

    def __eq__(self, other):
        return lib.signal_buffer_compare(self.value, other.value) == 0

    def __len__(self):
        if self.value:
            return lib.signal_buffer_len(self.value)
        return 0

    @property
    def data(self):
        return lib.signal_buffer_data(self.value)

    def append(self, data, data_len):
        if not self.ptr:
            raise ValueError("buffer not initialized")
        self._ptr[0] = lib.signal_buffer_append(self.value, data, data_len)

    def bin(self):
        return ffi.buffer(self.data, len(self))[:]

    def hex(self):
        return ffi.buffer(self.data, len(self))[:].hex()

    def b64(self):
        return b64encode(ffi.buffer(self.data, len(self)))

    @classmethod
    def fromhex(cls, serialized):
        return cls.create(bytes.fromhex(serialized))

    @classmethod
    def fromb64(cls, serialized):
        return cls.create(b64decode(serialized))

    @classmethod
    def fromptr(cls, ptr):
        buf = cls()
        buf._ptr[0] = lib.signal_buffer_copy(ptr)
        return buf

    @classmethod
    def create(cls, data, size=None):
        buf = cls()
        buf._ptr[0] = lib.signal_buffer_create(data,
                                               size if size else len(data))
        return buf
