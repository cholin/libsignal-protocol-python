from cdefs import ffibuilder, lib_name, lib_header_filename
from pathlib import Path
import sys

path_dirs = [Path(p) for p in sys.path]
# local_pkg_dirs = [Path('..') / lib_name / 'build' / 'src']

with open(lib_header_filename) as f:
    ffibuilder.set_source(
        "signal_protocol_cffi",
        f.read(),
        include_dirs=[str(p/'include'/'signal') for p in path_dirs],
        libraries=[lib_name],
        library_dirs=[str(p/'lib') for p in path_dirs],
    )

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
