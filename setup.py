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

from setuptools.command.build_py import build_py
from setuptools import setup
import subprocess
import platform
import pathlib
import sys
import os

THIS_DIRECTORY = str(pathlib.Path(__file__).parent.resolve())

BUILD_SCRIPT_PATH = str(pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")
                        .joinpath("scripts").joinpath("build"))

# Patched path as it is passed to msys2 bash
ENGINE_PATH = str(pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")).replace("\\", "/")

if (not sys.version_info[0] == 3) and (not sys.version_info[1] >= 6):
    sys.exit("Sorry, nfstream requires Python3.6+ versions.")

with open(os.path.join(THIS_DIRECTORY, 'README.md'), encoding='utf-8') as f:
    LONG_DESCRIPTION = f.read()

INSTALL_REQUIRES = ['cffi>=1.15.0',
                    'psutil>=5.8.0',
                    'dpkt>=1.9.7',
                    'numpy>=1.19.5']

if platform.python_implementation() == 'PyPy':  # This is mandatory to fix pandas issues with PyPy
    INSTALL_REQUIRES.append("pandas<=1.2.5")
else:
    INSTALL_REQUIRES.append("pandas>=1.1.5")


class BuildPyCommand(build_py):
    """ Custom build command to compile lib_engine dependencies."""
    def run(self):
        if not self.dry_run:
            if os.name != 'posix':  # Windows case
                os.environ["MSYSTEM"] = "MINGW64"
                msys = os.getenv("MSYS2_PATH")
                if msys is None:
                    os.environ["MSYS2_PATH"] = "C:/msys64"
                msys = os.getenv("MSYS2_PATH")
                build_script_command = r"""'{}'""".format(str(BUILD_SCRIPT_PATH) + "_windows.sh")
                subprocess.check_call(["{msys}/usr/bin/bash".format(msys=msys).replace("/", "\\"),
                                       "-l",
                                       build_script_command, ENGINE_PATH],
                                      shell=True)
            else:  # Linux, MacOS
                subprocess.check_call([str(BUILD_SCRIPT_PATH) + ".sh"], shell=True)
        build_py.run(self)


setup(
    cmdclass={
        "build_py": BuildPyCommand
    },
    name="nfstream",
    version='6.5.2',
    url='https://www.nfstream.org/',
    license='LGPLv3',
    description="A Flexible Network Data Analysis Framework",
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author='Zied Aouini',
    author_email='aouinizied@gmail.com',
    packages=['nfstream', 'nfstream.plugins', 'nfstream.engine'],
    setup_requires=["cffi>=1.15.0"],
    cffi_modules=["nfstream/engine/engine_build.py:ffi_builder"],
    install_requires=INSTALL_REQUIRES,
    include_package_data=True,
    platforms=["Linux", "Mac OS-X", "Windows", "Unix"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Topic :: Internet :: Log Analysis',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Scientific/Engineering :: Artificial Intelligence'
    ],
    project_urls={
        'GitHub': 'https://github.com/nfstream/nfstream',
    }
)
