from abc import ABC, abstractmethod
from cffi import StructBinder


class SenderKeyStore(StructBinder, ABC):
    cdecl = 'signal_protocol_sender_key_store*'

    @abstractmethod
    def store_sender_key(self, sender_key_name, record, record_len,
                         user_record, user_record_len):
        pass

    @abstractmethod
    def load_sender_key(self, record, user_record, sender_key_name):
        pass


class VolatileSenderKeyStore(SenderKeyStore):

    def store_sender_key(self, sender_key_name, record, record_len,
                         user_record, user_record_len):
        raise NotImplementedError

    def load_sender_key(self, record, user_record, sender_key_name):
        raise NotImplementedError
