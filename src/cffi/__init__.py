from signal_protocol_cffi import ffi, lib
from functools import partial
from abc import ABC, abstractmethod


class Pointer:
    """
    Generic pointer for c types

    Python class for generic c type allocations. Once this class gets garbage
    collected, the corresponding c type will be freed as well.

    This class is meant to be inherited from.

    Attributes
    ----------
    cdecl : str
        type of of your pointer
    """
    def __init__(self):
        super(Pointer, self).__init__()
        #print("Allocating " + self.cdecl)
        self._ptr = ffi.new(self.cdecl)

    def __copy__(self):
        raise RuntimeError("not copyable")

    @property
    def ptr(self):
        return self._ptr

    @property
    def value(self):
        return self._ptr[0]

    @property
    @abstractmethod
    def cdecl(self):
        pass

    def release(self):
        """
        Returns and release pointer from automatic memory management

        After calling this method the pointer is set to NULL and the returned
        pointer will not be freed automatically anymore. This may introduce a
        potential memory leak. May used if you want to give the responsiblity
        to free the pointer from python memory land to a C library.
        """
        ptr = self._ptr[0]
        self._ptr[0] = ffi.NULL
        return ptr


class RefCountedPointer(ABC):
    """
    Internal wrapper class for signal-protocol-c pointers.

    signal-protocol-c uses its own memory management system based on an
    internal ref count mechanism. It provides the following macros for that:

    * SIGNAL_REF
    * SIGNAL UNREF

    As we can't call macros directly, we use the underlying functions:

    * signal_type_ref()
    * signal_type_unref()

    This class is meant to inherit from. The following structs use the
    ref count system:

    * sender_key: sender_message_key, sender_chain_key
    * device_consistency: device_consistency_signature,
                          device_consistency_commitment,
                          device_consistency_message
    * session_pre_key: session_pre_key, session_signed_pre_key,
                       session_pre_key_bundle
    * rachtet: ratchet_chain_key, ratchet_root_key, ratchet_identity_key_pair
               symmetric_signal_protocol_parameters,
               alice_signal_protocol_parameters, bob_signal_protocol_parameters
    * session_record
    * sender_key_state
    * protocol: signal_message, pre_key_signal_message, sender_key_message,
                sender_key_distribution_message
    * curve: ec_public_key, ec_private_key, ec_key_pair
    * session_state
    * hkdf
    * sender_key_record
    * fingerprint: fingerprint, displayable_fingerprint, scannable_fingerprint

    Attributes
    ----------
    cdecl : str
        type of of your pointer
    """

    def __init__(self):
        super(RefCountedPointer, self).__init__()
        self._ptr = ffi.new(self.cdecl+'*')

    def __del__(self):
        if self.ptr:
            self.unref(self.ptr)

    def __copy__(self):
        p = self.__class__()
        p.ptr = self.ptr
        return p

    @property
    @abstractmethod
    def cdecl(self):
        pass

    @property
    def ptr(self):
        return self._ptr[0]

    @ptr.setter
    def ptr(self, value):
        if (self.ptr):
            self.unref(self.ptr)
        self.ref(value)
        self._ptr[0] = value

    @classmethod
    def ref(cls, ptr):
        casted = ffi.cast('signal_type_base *', ptr)
        lib.signal_type_ref(casted)

    @classmethod
    def unref(cls, ptr):
        casted = ffi.cast('signal_type_base *', ptr)
        lib.signal_type_unref(casted)


class GenericBinder(Pointer):
    """
    Generic binder class for structs in signal-protocol-c

    As these structs support user_data pointers, we can use this to store
    dynamically the actual python instance/handle here. Through this we can
    define methods in python which can be binded/invoked in signal-protocol-c.
    """
    def __init__(self):
        super(GenericBinder, self).__init__()
        self.expose_py_methods()

    @property
    def binding_methods(self):
        return []

    def expose_py_methods(self):
        for name in self.binding_methods:
            if not hasattr(self, name):
                raise AttributeError("Unimplemented method " + name)

            cls = self.__class__
            func = partial(cls._invoke, name)
            ffi.def_extern(name=name)(func)
            setattr(cls, '_'+name, staticmethod(func))
            #print("registered %s in %s" % (name, cls))

    @classmethod
    def _invoke(cls, name, *args):
        params = list(args)
        instance = ffi.from_handle(params.pop())  # get instance
        #print("\nInvoking %s.%s(" % (cls.__name__, name), *params, ")\n")
        return getattr(instance, name)(*params)


class StructBinder(GenericBinder):
    """
    Generic binder class for structs with function pointers.

    Similiar to the GenericBinder, StructBinder exposes python methods to
    c land. As there are well structured structs based on callback and member
    value entries, this class binds your python methods automatically to the
    corresponding callback / function pointer.
    """
    def __init__(self):
        super(StructBinder, self).__init__()

        # handle to be used as user_data. To prevent gc of this pointer we
        # store it in the instance itself
        self._handle = ffi.new_handle(self)
        self.ptr.user_data = self._handle

        self.expose_py_methods()
        self.bind_py_methods()

    @property
    @abstractmethod
    def cdecl(self):
        pass

    @property
    def binding_methods(self):
        # get methods automatically out of struct
        callbacks = [m for m in dir(self.ptr)
                     if ffi.typeof(getattr(self.ptr, m)).kind == 'function']
        return callbacks

    @property
    def ptr(self):
        return self._ptr

    def bind_py_methods(self):
        for method in self.binding_methods:
            #print("setting binding method", method, getattr(lib, method))
            setattr(self.ptr, method, getattr(lib, method))

    def destroy_func(self):
        pass
        #print("destroyed_func called()")