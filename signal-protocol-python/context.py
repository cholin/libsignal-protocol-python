from cffi import ffi, lib, GenericBinder, invoke
from threading import RLock
from abc import ABC, abstractmethod
from crypto import CryptoPyProvider


class SignalContext(GenericBinder, ABC):
    cdecl = 'signal_context**'
    binding_methods = ['signal_lock', 'signal_unlock', 'signal_log']

    def __init__(self, **kwargs):
        super(SignalContext, self).__init__(**kwargs)

        # handle to be used as user_data. To prevent gc of this pointer we
        # store it in the instance itself
        self._handle = ffi.new_handle(self)
        invoke('signal_context_create', self.ptr, self._handle)

        invoke('signal_context_set_crypto_provider', self.value,
               self.get_crypto_provider())

        invoke('signal_context_set_locking_functions', self.value,
               lib.signal_lock, lib.signal_unlock)

        invoke('signal_context_set_log_function', self.value, lib.signal_log)

    def __del__(self):
        invoke('signal_context_destroy', self.value)

    @abstractmethod
    def get_crypto_provider(self):
        pass

    @abstractmethod
    def signal_lock(self):
        pass

    @abstractmethod
    def signal_unlock(self):
        pass

    @abstractmethod
    def signal_log(self, level, msg, msg_len):
        pass


class SignalPyContext(SignalContext):
    def __init__(self):
        self.rlock = RLock()
        super(SignalPyContext, self).__init__()

    def get_crypto_provider(self):
        self.crypto_provider = CryptoPyProvider()  # keep ref to keep it alive
        return self.crypto_provider.ptr

    def signal_lock(self):
        self.rlock.acquire()

    def signal_unlock(self):
        self.rlock.release()

    def signal_log(self, level, msg, msg_len):
        categories = {
            lib.SG_LOG_ERROR:   'ERROR',
            lib.SG_LOG_WARNING: 'WARNING',
            lib.SG_LOG_NOTICE:  'NOTICE',
            lib.SG_LOG_INFO:    'INFO',
            lib.SG_LOG_DEBUG:   'DEBUG'
        }
        message = ffi.buffer(msg, msg_len)[:].decode()
        print("[%s]\t%s" % (categories[level], message))
