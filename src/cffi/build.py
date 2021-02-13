from cdefs import ffi
from pathlib import Path
import sys
path_dirs = [Path(p) for p in sys.path]
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
    include_dirs=[str(p/'include'/'signal') for p in path_dirs], #['libsignal-protocol-c/src'],
    libraries=['signal-protocol-c'],
    library_dirs=[str(p/'lib') for p in path_dirs] +['libsignal-protocol-c/build/src'],
 )

if __name__ == "__main__":
    ffi.compile(verbose=True)
