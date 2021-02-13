from setuptools import setup

setup(
    name='signal_protocol_cffi',
    version='0.1',
    setup_requires=['cffi>=1.0.0'],
    install_requires=['signal_protocol_c', 'cffi>=1.0.0'],
    cffi_modules=['build.py:ffibuilder'],
    zip_safe=False,
)
