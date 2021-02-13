from abc import ABC, abstractmethod
from cffi import ffi, StructBinder
from copy import copy
from buffer import Buffer


class SessionStore(StructBinder, ABC):
    cdecl = 'signal_protocol_session_store*'

    @abstractmethod
    def load_session_func(self, record, user_record, address):
        pass

    @abstractmethod
    def get_sub_device_sessions_func(self, sessions, name, name_len):
        pass

    @abstractmethod
    def store_session_func(self, address, record, record_len, user_record,
                           user_record_len):
        pass

    @abstractmethod
    def contains_session_func(self, address):
        pass

    @abstractmethod
    def delete_session_func(self, address):
        pass

    @abstractmethod
    def delete_all_sessions_func(self, name, name_len):
        pass


class VolatileSessionStore(SessionStore):

    def __init__(self):
        super(VolatileSessionStore, self).__init__()
        self.sessions = {}

    @staticmethod
    def join_address(address):
        name = ffi.buffer(address.name, address.name_len)[:]
        return name + b'_' + bytes([address.device_id])

    def load_session_func(self, record, user_record, address):
        key = self.join_address(address)
        if key not in self.sessions:
            return 0

        record[0] = copy(self.sessions[key]).release()

        return 1

    def get_sub_device_sessions_func(self, sessions, name, name_len):
        raise NotImplementedError

    def store_session_func(self, address, record, record_len, user_record,
                           user_record_len):
        key = self.join_address(address)
        self.sessions[key] = Buffer.create(record, record_len)
        return 0

    def contains_session_func(self, address):
        key = self.join_address(address)
        if key in self.sessions:
            return 1
        return 0

    def delete_session_func(self, address):
        key = self.join_address(address)
        if key not in self.sessions:
            return 0

        del self.sessions[key]
        return 1

    def delete_all_sessions_func(self, name, name_len):
        self.sessions.clear
        return 0
