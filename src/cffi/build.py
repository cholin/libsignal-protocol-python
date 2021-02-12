from cdefs import ffi
from pathlib import Path

source_path = Path(__file__).resolve()
source_dir = source_path.parent / '..' / '..'

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
    include_dirs=[str(source_dir / 'libs' / 'libsignal-protocol-c' / 'src')],
    libraries=['signal-protocol-c'],
    library_dirs=[str(source_dir / 'build' / 'src')]
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
