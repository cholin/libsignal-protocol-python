from cdefs import ffi
from pathlib import Path
import sys

lib_name = 'signal-protocol-c'
path_dirs = [Path(p) for p in sys.path]
# local_pkg_dirs = [Path('..') / lib_name / 'build' / 'src']

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
    include_dirs=[str(p/'include'/'signal') for p in path_dirs],
    libraries=[lib_name],
    library_dirs=[str(p/'lib') for p in path_dirs],
 )

if __name__ == "__main__":
    ffi.compile(verbose=True)
