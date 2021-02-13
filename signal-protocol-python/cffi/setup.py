from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from pathlib import Path
import subprocess


class CMakeExtension(Extension):
    def __init__(self, name):
        super(CMakeExtension, self).__init__(name, sources=[])
        self.source_dir = Path(name).resolve()


class CMakeBuild(build_ext):
    def build_extension(self, ext):
        Path(self.build_temp).mkdir(parents=True, exist_ok=True)
        
        extdir = Path(self.get_ext_fullpath(ext.name)).resolve().parent
        # '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={}'.format(extdir),
        # '-B{}'.format(extdir)

        cmake_args = [
            '-DCMAKE_INSTALL_PREFIX={}'.format(extdir),
            '-DCMAKE_BUILD_TYPE={}'.format('Debug' if self.debug else 'Release'),
        ]
        subprocess.check_call(
            ["cmake", ext.source_dir] + cmake_args, cwd=self.build_temp
        )

        subprocess.check_call(
            ["make", "install"], cwd=self.build_temp
        )


setup(
    # name='signal_protocol_cffi',
    # version='0.1',
    # cffi_modules=["build.py:ffi"],
    # install_requires=['signal_protocol_c', 'cffi'],
    # include_package_data=True,
    name='signal_protocol_c',
    ext_modules=[CMakeExtension("libsignal-protocol-c")],
    cmdclass={"build_ext": CMakeBuild},
    zip_safe=False,
)
