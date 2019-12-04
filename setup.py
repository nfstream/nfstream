#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: setup.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os
import subprocess
import shutil


if os.name != 'posix':
    sys.exit("Sorry, Windows is not supported by nfstream.")

if (not sys.version_info[0] == 3) and (not sys.version_info[1] >= 6):  # avoid py27 wheels generation on macos runners
    sys.exit("Sorry, nfstream requires Python3.6+ versions.")

try:
    from setuptools import setup
    from setuptools.command.build_ext import build_ext
    from setuptools.command.build_py import build_py
    use_setuptools = True
except ImportError:
    from distutils.core import setup
    from distutils.command.build_ext import build_ext
    from distutils.command.build_py import build_py
    use_setuptools = False


try:
    with open('README.rst', 'rt') as readme:
        description = '\n' + readme.read()
except IOError:
    # maybe running setup.py from some other dir
    description = ''


class BuildPyCommand(build_py):
    def run(self):
        self.run_command('nDPI')
        build_py.run(self)


class BuildNdpiCommand(build_ext):
    def run(self):
        subprocess.check_call(['git', 'clone', '--branch', '3.0-stable', 'https://github.com/ntop/nDPI.git'])
        os.chdir('nDPI/')
        subprocess.check_call(['./autogen.sh'])
        subprocess.check_call(['./configure'])
        subprocess.check_call(['make'])
        os.chdir('src/')
        os.chdir('lib/')
        shutil.copy2('libndpi.so', '../../../nfstream/libs/')
        os.chdir('..')
        os.chdir('..')
        os.chdir('..')
        shutil.rmtree('nDPI/', ignore_errors=True)
        build_ext.run(self)


needs_pytest = {'pytest', 'test', 'ptr'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []

python_requires = '>=3.6'
install_requires = ['cffi>=1.13.1',
                    'pyzmq>=18.1.1']

if os.getenv('READTHEDOCS'):
    install_requires.append('numpydoc>=0.8')
    install_requires.append('sphinx_rtd_theme>=0.4.3')

try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel

    class bdist_wheel(_bdist_wheel):
        def get_tag(self):
            tag = _bdist_wheel.get_tag(self)
            pypi_compliant_tag = list(tag)
            if 'linux' == pypi_compliant_tag[2][0:5]:
                pypi_compliant_tag[2] = pypi_compliant_tag[2].replace("linux", "manylinux1")
            pypi_compliant_tag = tuple(pypi_compliant_tag)
            return pypi_compliant_tag

        def finalize_options(self):
            _bdist_wheel.finalize_options(self)
            self.root_is_pure = False


except ImportError:
    bdist_wheel = None

setup(
    name="nfstream",
    version='2.0.2',
    url='https://github.com/aouinizied/nfstream.git',
    license='LGPLv3',
    description="A flexible and powerful network data analysis framework",
    long_description=description,
    author='Zied Aouini',
    author_email='aouinizied@gmail.com',
    packages=['nfstream'],
    install_requires=install_requires,
    cmdclass={'nDPI': BuildNdpiCommand, 'build_py': BuildPyCommand, 'bdist_wheel': bdist_wheel},
    setup_requires=pytest_runner,
    tests_require=['pytest>=5.0.1'],
    include_package_data=True,
    platforms=["Linux", "Mac OS-X", "Unix"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Scientific/Engineering :: Artificial Intelligence'
    ],
    project_urls={
        'Documentation': 'https://nfstream.readthedocs.io',
    }
)