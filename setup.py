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

if (not sys.version_info[0] == 3) and (not sys.version_info[1] >= 6):
    sys.exit("Sorry, nfstream requires Python3.6+ versions.")


from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py


from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


class BuildPyCommand(build_py):
    def run(self):
        self.run_command('nDPI')
        build_py.run(self)


class BuildNdpiCommand(build_ext):
    def run(self):
        if os.name != 'posix':  # Windows case
            pass
        else:
            subprocess.check_call(['git', 'clone', '--branch', 'dev', 'https://github.com/ntop/nDPI.git'])
            os.chdir('nDPI/')
            print("Setting up nDPI: autogen.")
            subprocess.check_call(['./autogen.sh'])
            os.chdir('src/')
            os.chdir('lib/')
            subprocess.check_call(['make'])
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
    print('Warning: cannot import "wheel" package to build platform-specific wheel')
    print('Install the "wheel" package to fix this warning')
    bdist_wheel = None

cmdclass = {'nDPI': BuildNdpiCommand, 'build_py': BuildPyCommand, 'bdist_wheel': bdist_wheel} if bdist_wheel is not None else dict()

setup(
    name="nfstream",
    version='3.1.0',
    url='https://github.com/aouinizied/nfstream.git',
    license='LGPLv3',
    description="A flexible and powerful network data analysis framework",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Zied Aouini',
    author_email='aouinizied@gmail.com',
    packages=['nfstream'],
    install_requires=install_requires,
    cmdclass=cmdclass,
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