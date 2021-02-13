import numbers
from cffi import lib, ffi


class LibSignalError(Exception):
    code = lib.SG_ERR_UNKNOWN


class NoMemory(LibSignalError):
    code = lib.SG_ERR_NOMEM


class InvalidArgument(LibSignalError):
    code = lib.SG_ERR_INVAL


class DuplicateMessageError(LibSignalError):
    code = lib.SG_ERR_DUPLICATE_MESSAGE


class InvalidKeyError(LibSignalError):
    code = lib.SG_ERR_INVALID_KEY


class InvalidKeyIDError(LibSignalError):
    code = lib.SG_ERR_INVALID_KEY_ID


class InvalidMACError(LibSignalError):
    code = lib.SG_ERR_INVALID_MAC


class InvalidMessageError(LibSignalError):
    code = lib.SG_ERR_INVALID_MESSAGE


class InvalidVersionError(LibSignalError):
    code = lib.SG_ERR_INVALID_VERSION


class LegacyMessageError(LibSignalError):
    code = lib.SG_ERR_LEGACY_MESSAGE


class NoSessionError(LibSignalError):
    code = lib.SG_ERR_NO_SESSION


class StaleKeyExchangeError(LibSignalError):
    code = lib.SG_ERR_STALE_KEY_EXCHANGE


class UntrustedIdentityError(LibSignalError):
    code = lib.SG_ERR_UNTRUSTED_IDENTITY


class VrfSignatureVerificationError(LibSignalError):
    code = lib.SG_ERR_VRF_SIG_VERIF_FAILED


class InvalidProtoBufError(LibSignalError):
    code = lib.SG_ERR_INVALID_PROTO_BUF


class FingerprintVersionMismatchError(LibSignalError):
    code = lib.SG_ERR_FP_VERSION_MISMATCH


class FingerprintIdentificationMismatchError(LibSignalError):
    code = lib.SG_ERR_FP_IDENT_MISMATCH


def raise_on_error(code, nullable=False):
    error_clses = [LibSignalError, NoMemory, InvalidArgument, DuplicateMessageError, InvalidKeyError, InvalidKeyIDError, InvalidMACError, InvalidMessageError, InvalidVersionError, LegacyMessageError,
                   NoSessionError, StaleKeyExchangeError, UntrustedIdentityError, VrfSignatureVerificationError, InvalidProtoBufError, FingerprintVersionMismatchError, FingerprintIdentificationMismatchError]

    if not nullable and code == ffi.NULL:
        code = lib.SG_ERR_UNKNOWN

    # error codes are negative integers, return in other cases
    if not isinstance(code, numbers.Number) or code >= 0:
        return code

    for cls in error_clses:
        if cls.code == code:
            raise cls()
