from .cffi import ffi, Pointer


class Address(Pointer):
    cdecl = 'signal_protocol_address*'

    def __eq__(self, other):
        return self.name == other.name and \
               self.device_id == other.device_id

    def __copy__(self):
        return Address.create(self.name, self.device_id)

    @property
    def name(self):
        return ffi.buffer(self.ptr.name, self.ptr.name_len)[:]

    @name.setter
    def name(self, name):
        self._name = name
        self.ptr.name = ffi.from_buffer(name)
        self.ptr.name_len = len(name)

    @property
    def device_id(self):
        return self.ptr.device_id

    @device_id.setter
    def device_id(self, device_id):
        self.ptr.device_id = device_id

    def bin(self):
        return b'%b-%d' % (self.name, self.id)

    @classmethod
    def create(cls, name, device_id):
        address = cls()
        address.name = name
        address.device_id = device_id
        return address
