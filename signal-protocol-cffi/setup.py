from setuptools import setup

setup(
    name='signal_protocol_cffi',
    version='0.1',
    cffi_modules=["build.py:ffi"],
    install_requires=['signal_protocol_c', 'cffi'],
    include_package_data=True,
    zip_safe=False,
)
