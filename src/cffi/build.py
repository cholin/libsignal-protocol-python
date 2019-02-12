from cdefs import ffi

ffi.set_source(
    "signal_protocol_cffi",
    """

#include <stdlib.h>
#include "signal_protocol.h"
#include "key_helper.h"
#include "session_builder.h"
#include "session_cipher.h"
#include "protocol.h"
    """,
    include_dirs=['../../libs/libsignal-protocol-c/src/'],
    libraries=['signal-protocol-c'],
    library_dirs=['../../libs/libsignal-protocol-c/build/src/']
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
