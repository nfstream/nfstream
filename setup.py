import sys
import os
import subprocess
import shutil
from itertools import chain
from io import open
import glob

if os.name != 'posix':
    sys.exit("Sorry, Windows is not supported by nfstream.")

try:
    from setuptools import setup, Extension
    from setuptools.command.build_ext import build_ext
    from setuptools.command.build_py import build_py
    use_setuptools = True
except ImportError:
    from distutils.core import setup, Extension
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
        os.chdir('python/')
        subprocess.check_call(['make'])
        shutil.copy2('ndpi_wrap.so', '../../nfstream/')
        os.chdir('..')
        os.chdir('..')
        shutil.rmtree('nDPI/', ignore_errors=True)
        build_ext.run(self)


needs_pytest = {'pytest', 'test', 'ptr'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []

python_requires = '>=3.5'
install_requires = ['lru-dict>=1.1.6',
                    'dpkt>=1.9.2',
                    'numpydoc>=0.8',
                    'sphinx_rtd_theme>=0.4.3',
                    'colorama>=0.4.1',
                    'cython>=0.29.13']


def recursive_search_dirs(dirs, target_files):
    """Recursive search directories"""
    for d in dirs:
        r = recursive_search(d, target_files)
        if r:
            return r


def recursive_search(path, target_files):
    """Recursively search for files"""
    for root, _dirs, files in os.walk(path):
        for filename in files:
            if filename in target_files:
                return os.path.join(root, filename)


def find_prefix_and_pcap_h():
    prefixes = chain.from_iterable((
        ('/usr', sys.prefix),
        glob.glob('/opt/libpcap*'),
        glob.glob('../libpcap*'),
        glob.glob('../wpdpack*'),
        glob.glob('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/*'),
        glob.glob('/Library/Developer/CommandLineTools/SDKs/*'),
    ))

    # Find 'pcap.h'
    for prefix in prefixes:
        search_dirs = (
            os.path.join(prefix, 'local', 'include'),
            os.path.join(prefix, 'usr', 'include'),
            os.path.join(prefix, 'include'),
            prefix,
        )

        pcap_h = recursive_search_dirs(search_dirs, ['pcap.h'])
        if pcap_h:
            print("Found pcap headers in %s" % pcap_h)
            return (prefix, pcap_h)
    print("pcap.h not found")
    sys.exit(1)


def find_lib_path_and_file(prefix):
    if sys.maxsize > 2 ** 32:
        candidates = [
            'lib64',
            'lib/x64',  # wpdpack
            'lib/x86_64-linux-gnu'
            'lib',
            'lib/i386-linux-gnu',
            ''
        ]
    else:
        candidates = [
            'lib',
            'lib/i386-linux-gnu',
            ''
        ]
    lib_sub_dirs = [
        os.path.join(prefix, d) for d in candidates
    ]
    # For Mac OSX the default system pcap lib is in /usr/lib
    lib_sub_dirs.append('/usr/lib')

    lib_files = [
        'libpcap.a',
        'libpcap.so',
        'libpcap.dylib',
        'wpcap.lib'
    ]
    lib_file_path = recursive_search_dirs(lib_sub_dirs, lib_files)
    if not lib_file_path:
        print("None of the following found: %s" % lib_files)
        sys.exit(1)
        return
    print("Found libraries in %s" % lib_file_path)

    lib_path = os.path.dirname(lib_file_path)
    lib_file = os.path.basename(lib_file_path)
    return lib_path, lib_file


def find_define_macros(pcap_h):
    alternative = os.path.join(os.path.dirname(pcap_h), 'pcap', 'pcap.h')
    if os.path.exists(alternative):
        for macro in find_define_macros(alternative):
            yield macro
    with open(pcap_h, 'r',
              encoding='utf-8',
              errors='surrogateescape') as fi:
        for line in fi.readlines():
            if 'pcap_compile_nopcap(' in line:
                print("found pcap_compile_nopcap function")
                yield ('HAVE_PCAP_COMPILE_NOPCAP', 1)
            elif 'pcap_setnonblock(' in line:
                print("found pcap_setnonblock")
                yield ('HAVE_PCAP_SETNONBLOCK', 1)
            elif 'pcap_setdirection(' in line:
                print("found pcap_setdirection")
                yield ('HAVE_PCAP_SETDIRECTION', 1)
            elif 'pcap_get_tstamp_precision(' in line:
                print("found pcap_get_tstamp_precision function")
                yield ('HAVE_PCAP_TSTAMP_PRECISION', 1)


def get_extension():
    prefix, pcap_h = find_prefix_and_pcap_h()
    lib_path, lib_file = find_lib_path_and_file(prefix)

    if lib_file == 'wpcap.lib':
        libraries = ['wpcap', 'iphlpapi']
        extra_compile_args = ['-DWIN32', '-DWPCAP', '-D_CRT_SECURE_NO_WARNINGS']
    else:
        libraries = ['pcap']
        extra_compile_args = []

    return Extension(
        name='ppcap',
        sources=['nfstream/pcap.c', 'nfstream/pcap_ex.c'],
        include_dirs=[os.path.dirname(pcap_h)],
        define_macros=list(find_define_macros(pcap_h)),
        library_dirs=[lib_path],
        libraries=libraries,
        extra_compile_args=extra_compile_args,
    )


setup(
    name="nfstream",
    version='0.5.0',
    url='https://github.com/aouinizied/nfstream.git',
    license='LGPLv3',
    description="A flexible and powerful network data analysis library",
    long_description=description,
    author='Zied Aouini',
    author_email='aouinizied@gmail.com',
    packages=['nfstream'],
    install_requires=install_requires,
    ext_modules=[get_extension()],
    cmdclass={'nDPI': BuildNdpiCommand, 'build_py': BuildPyCommand},
    setup_requires=pytest_runner,
    tests_require=['pytest>=5.0.1'],
    include_package_data=True,
    platforms='any',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Topic :: Scientific/Engineering :: Artificial Intelligence'
    ]
)
