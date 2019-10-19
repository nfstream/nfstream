import sys
import os
import subprocess
import shutil


if os.name != 'posix':
    sys.exit("Sorry, Windows is not supported by nfstream.")

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
                    'colorama>=0.4.1']
if not os.getenv('READTHEDOCS'):
    install_requires.append('pypcap>=1.2.3')


setup(
    name="nfstream",
    version='0.1.0',
    url='https://github.com/aouinizied/nfstream.git',
    license='LGPLv3',
    description="A flexible and powerful network data analysis library",
    long_description=description,
    author='Zied Aouini',
    author_email='aouinizied@gmail.com',
    packages=['nfstream'],
    install_requires=install_requires,
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
