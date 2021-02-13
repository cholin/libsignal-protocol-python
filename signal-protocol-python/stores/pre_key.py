from abc import ABC, abstractmethod
from cffi import lib, StructBinder
from copy import copy
from buffer import Buffer


class PreKeyStore(StructBinder, ABC):
    cdecl = 'signal_protocol_pre_key_store*'

    @abstractmethod
    def load_pre_key(self, record, pre_key_id):
        pass

    @abstractmethod
    def store_pre_key(self, pre_key_id, record, record_len):
        pass

    @abstractmethod
    def contains_pre_key(self, pre_key_id):
        pass

    @abstractmethod
    def remove_pre_key(self, pre_key_id):
        pass


class SignedPreKeyStore(StructBinder, ABC):
    cdecl = 'signal_protocol_signed_pre_key_store*'

    @abstractmethod
    def load_signed_pre_key(self, record, signed_pre_key_id):
        pass

    @abstractmethod
    def store_signed_pre_key(self, signed_pre_key_id, record, record_len):
        pass

    @abstractmethod
    def contains_signed_pre_key(self, signed_pre_key_id):
        pass

    @abstractmethod
    def remove_signed_pre_key(self, signed_pre_key_id):
        pass


class VolatilePreKeyStore(PreKeyStore):
    def __init__(self):
        super(VolatilePreKeyStore, self).__init__()
        self._keys = {}

    def load_pre_key(self, record, pre_key_id):
        if pre_key_id not in self._keys:
            return lib.SG_ERR_INVALID_KEY_ID
        record[0] = copy(self._keys[pre_key_id]).release()
        return lib.SG_SUCCESS

    def store_pre_key(self, pre_key_id, record, record_len):
        self._keys[pre_key_id] = Buffer.create(record, record_len)
        return 1

    def contains_pre_key(self, pre_key_id):
        if pre_key_id in self._keys:
            return 1
        return 0

    def remove_pre_key(self, pre_key_id):
        if pre_key_id not in self._keys:
            return 1
        del self._keys[pre_key_id]
        return 0


class VolatileSignedPreKeyStore(SignedPreKeyStore, VolatilePreKeyStore):

    def load_signed_pre_key(self, record, signed_pre_key_id):
        return self.load_pre_key(record, -signed_pre_key_id)

    def store_signed_pre_key(self, signed_pre_key_id, record, record_len):
        return self.store_pre_key(-signed_pre_key_id, record, record_len)

    def contains_signed_pre_key(self, signed_pre_key_id):
        return self.contains_pre_key(-signed_pre_key_id)

    def remove_signed_pre_key(self, signed_pre_key_id):
        return self.remove_pre_key(-signed_pre_key_id)
