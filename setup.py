"""
------------------------------------------------------------------------------------------------------------------------
setup.py
Copyright (C) 2019-21 - NFStream Developers
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
import subprocess

if (not sys.version_info[0] == 3) and (not sys.version_info[1] >= 6):
    sys.exit("Sorry, nfstream requires Python3.6+ versions.")


from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py


this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


def setup_engine_cc():
    platform_compiler = "gcc"
    if sys.platform == 'darwin':
        platform_compiler = "clang"
    print("\nSetting up engine_cc. Platform: {plat}, Byteorder: {bo}".format(plat=sys.platform, bo=sys.byteorder))
    subprocess.check_call([platform_compiler, '-I/usr/local/include/ndpi', '-shared', '-o',
                           'nfstream/engine/engine_cc.so',
                           '-g', '-fPIC', '-DPIC', '-O2', '-Wall', 'nfstream/engine/engine_cc.c',
                           # Required compiled static libs
                           '/usr/local/lib/libpcap.a',
                           '/usr/local/lib/libndpi.a',
                           '/usr/local/lib/libgcrypt.a',
                           '/usr/local/lib/libgpg-error.a'
                           ])


class BuildPyCommand(build_py):
    def run(self):
        self.run_command('build_native')
        build_py.run(self)


class BuildNativeCommand(build_ext):
    def run(self):
        if os.name != 'posix':  # Windows case
            pass
        else:
            setup_engine_cc()
        build_ext.run(self)


needs_pytest = {'pytest', 'test', 'ptr'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []
python_requires = '>=3.6'
# Change hash by this line.
install_requires = ['cffi>=1.14.6',
                    'numpy>=1.19.5',
                    'pandas>=1.1.5',
                    'psutil>=5.8.0',
                    'dpkt>=1.9.7']

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
    version='6.3.4',
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
    platforms=["Linux", "Mac OS-X", "Unix"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Scientific/Engineering :: Artificial Intelligence'
    ],
    project_urls={
        'GitHub': 'https://github.com/nfstream/nfstream',
    }
)
