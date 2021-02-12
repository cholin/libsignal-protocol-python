from setuptools import setup
from pathlib import Path
source_path = Path(__file__).resolve()
source_dir = source_path.parent / '..' / '..'
setup(
    name = 'signal-protocol-cffi',
    version = '0.1',
    cffi_modules=["./build.py:ffi"],
    install_requires = ['cffi']
)
