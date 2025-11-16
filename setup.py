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

from setuptools import setup
import platform
import pathlib
import sys
import os

THIS_DIRECTORY = str(pathlib.Path(__file__).parent.resolve())

if (not sys.version_info[0] == 3) and (not sys.version_info[1] >= 9):
    sys.exit("Sorry, nfstream requires Python3.9+ versions.")

with open(os.path.join(THIS_DIRECTORY, "README.md"), encoding="utf-8") as f:
    LONG_DESCRIPTION = f.read()

INSTALL_REQUIRES = ["cffi>=1.15.0", "psutil>=5.8.0", "dpkt>=1.9.7", "numpy>=1.19.5", "pandas>=1.1.5"]


setup(
    name="nfstream",
    version="6.5.4",
    url="https://www.nfstream.org/",
    license="LGPLv3",
    description="A Flexible Network Data Analysis Framework",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author="Zied Aouini",
    author_email="aouinizied@gmail.com",
    packages=["nfstream", "nfstream.plugins", "nfstream.engine"],
    setup_requires=["cffi>=1.15.0"],
    cffi_modules=["nfstream/engine/engine_build.py:ffi_builder"],
    install_requires=INSTALL_REQUIRES,
    include_package_data=True,
    platforms=["Linux", "Mac OS-X", "Windows", "Unix"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Intended Audience :: Telecommunications Industry",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: Log Analysis",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    project_urls={
        "GitHub": "https://github.com/nfstream/nfstream",
    },
)
