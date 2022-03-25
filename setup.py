"""
------------------------------------------------------------------------------------------------------------------------
setup.py
Copyright (C) 2019-22 - NFStream Developers
This file is part of NFStream, a Flexible Network Data Analysis Framework (https://www.nfstream.org/).
NFStream is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
NFStream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
"""

import sys
import os
import platform
import pathlib
import shutil
import subprocess
from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py

if (not sys.version_info[0] == 3) and (not sys.version_info[1] >= 6):
    sys.exit("Sorry, nfstream requires Python3.6+ versions.")

BUILD_SCRIPT_PATH = pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")\
    .joinpath("dependencies").joinpath("build.sh")

DEPENDENCIES_DIR = pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")\
    .joinpath("dependencies")

ENGINE_DIR = pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")

THIS_DIRECTORY = os.path.abspath(os.path.dirname(__file__))


with open(os.path.join(THIS_DIRECTORY, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


def setup_engine_cc():
    platform_compiler = "gcc"
    if sys.platform == 'darwin':
        platform_compiler = "clang"
    print("\nSetting up engine_cc. Platform: {plat}, Byteorder: {bo}".format(plat=sys.platform, bo=sys.byteorder))
    subprocess.check_call([platform_compiler,
                           '-I' + str(DEPENDENCIES_DIR.joinpath("nDPI").joinpath("src").joinpath("include")),
                           '-I' + str(DEPENDENCIES_DIR.joinpath("libpcap")),
                           '-shared',
                           '-o', str(ENGINE_DIR.joinpath("engine_cc.so")),
                           '-g', '-fPIC', '-DPIC', '-O2', '-Wall',
                           str(ENGINE_DIR.joinpath("engine_cc.c")),
                           # Required compiled static libs
                           str(DEPENDENCIES_DIR.joinpath("libpcap").joinpath("libpcap.a")),
                           str(DEPENDENCIES_DIR.joinpath("nDPI").joinpath("src").joinpath("lib").joinpath("libndpi.a")),
                           str(DEPENDENCIES_DIR.joinpath("libgcrypt").joinpath("src").joinpath(".libs")\
                               .joinpath("libgcrypt.a")),
                           str(DEPENDENCIES_DIR.joinpath("libgpg-error").joinpath("src").joinpath(".libs")\
                               .joinpath("libgpg-error.a")),
                           ])


class BuildPyCommand(build_py):
    def run(self):
        self.run_command('build_native')
        build_py.run(self)


class BuildNativeCommand(build_ext):
    def run(self):
        # Build Dependencies
        if os.name != 'posix':  # Windows case, no libpcap
            build_script_command = r"""'{}'""".format(str(BUILD_SCRIPT_PATH) + ' --skip-libpcap')
            msys2 = shutil.which('msys2')
            subprocess.check_call([msys2, "-c", build_script_command], shell=False)
        else:
            subprocess.check_call([str(BUILD_SCRIPT_PATH)])
        # Build engine
        setup_engine_cc()
        build_ext.run(self)


needs_pytest = {'pytest', 'test', 'ptr'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []
install_requires = ['cffi>=1.14.6',
                    'psutil>=5.8.0',
                    'dpkt>=1.9.7']

# This is mandatory to fix both issues with numpy using Accelerate backend on macos and pandas issues with PyPy
if sys.platform == 'darwin':
    install_requires.append("numpy<=1.18.5")
else:
    install_requires.append("numpy>=1.19.5")

if platform.python_implementation() == 'PyPy':
    install_requires.append("pandas<=1.2.5")
else:
    install_requires.append("pandas>=1.1.5")

try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel

    class bdist_wheel(_bdist_wheel):
        def get_tag(self):
            tag = _bdist_wheel.get_tag(self)
            pypi_compliant_tag = list(tag)
            if 'linux' == pypi_compliant_tag[2][0:5]:
                pypi_compliant_tag[2] = pypi_compliant_tag[2].replace("linux", "manylinux1")
            if pypi_compliant_tag[2] == "manylinux1_aarch64":
                pypi_compliant_tag[2] = "manylinux2014_aarch64"
            if pypi_compliant_tag[2] == "manylinux1_armv7l":
                pypi_compliant_tag[2] = "manylinux2014_armv7l"
            pypi_compliant_tag = tuple(pypi_compliant_tag)
            return pypi_compliant_tag

        def finalize_options(self):
            _bdist_wheel.finalize_options(self)
            self.root_is_pure = False


except ImportError:
    print('Warning: cannot import "wheel" package to build platform-specific wheel')
    print('Install the "wheel" package to fix this warning')
    bdist_wheel = None

cmdclass = {'build_native': BuildNativeCommand,
            'build_py': BuildPyCommand,
            'bdist_wheel': bdist_wheel} if bdist_wheel is not None else dict()

setup(
    name="nfstream",
    version='6.4.3',
    url='https://www.nfstream.org/',
    license='LGPLv3',
    description="A Flexible Network Data Analysis Framework",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Zied Aouini',
    author_email='aouinizied@gmail.com',
    packages=['nfstream', 'nfstream.plugins', 'nfstream.engine'],
    install_requires=install_requires,
    cmdclass=cmdclass,
    setup_requires=pytest_runner,
    tests_require=['pytest>=5.0.1'],
    include_package_data=True,
    platforms=["Linux", "Mac OS-X", "Windows", "Unix"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Scientific/Engineering :: Artificial Intelligence'
    ],
    project_urls={
        'GitHub': 'https://github.com/nfstream/nfstream',
    }
)
