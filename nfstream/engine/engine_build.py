"""
------------------------------------------------------------------------------------------------------------------------
engine_build.py
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

from cffi import FFI
import subprocess
import pathlib
import shutil
import sys
import os


BUILD_SCRIPT_PATH = str(pathlib.Path(__file__).parent.resolve().  # Current directory
                        joinpath("scripts").joinpath("build")).replace("\\", "/").replace("//", "/")  # Patch for msys2

NDPI_INCLUDES = """
#include "ndpi_main.h"
#include "ndpi_typedefs.h"
#include "ndpi_api.h"
"""

PCAP_INCLUDES = """
struct pcap;
typedef struct pcap pcap_t;
"""

TYPES_DEF = """
typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
typedef uint8_t u_char;
typedef unsigned u_int;
struct in_addr {
  unsigned long s_addr;
};
struct in6_addr {
  unsigned char s6_addr[16];
};
"""

if os.name != 'posix':
    EXTENSION = "dll"
else:
    EXTENSION = "so"

ENGINE_PATH = "/engine_cc.{ext}".format(ext=EXTENSION)

INCLUDE_DIR = pathlib.Path(__file__).parent.resolve().joinpath("dependencies").joinpath("nDPI").joinpath("src")\
    .joinpath("include")


def build_engine_cc():
    if os.name != 'posix':  # Windows case, no libpcap
        build_script_command = r"""'{}'""".format(BUILD_SCRIPT_PATH + "_windows.sh")
        msys2 = shutil.which('msys2')
        subprocess.check_call([msys2, "-l", "-c", build_script_command], shell=True)
    else:
        if sys.platform == 'darwin':
            subprocess.check_call([BUILD_SCRIPT_PATH + "_macos.sh"], shell=True)
        else:
            subprocess.check_call([BUILD_SCRIPT_PATH + "_linux.sh"], shell=True)


ffi_builder = FFI()
build_engine_cc()

NDPI_CDEF = ""
with open(os.path.join(os.path.dirname(__file__), "ndpi.cdef")) as ndpi_cdef:
    with open(os.path.join(os.path.dirname(__file__), "engine_cc.h")) as engine_cc_h:
        ENGINE_SOURCE = ""
        if os.name == 'posix':  # Windows case, no libpcap
            ENGINE_SOURCE = PCAP_INCLUDES
        NDPI_CDEF += ndpi_cdef.read()
        ENGINE_SOURCE += "".join(engine_cc_h.read().split("//CFFI_ENGINE_EXCLUDE")[2::2])

ffi_builder.set_source("_engine",
                       NDPI_INCLUDES + NDPI_CDEF.split("//CFFI.NDPI_MODULE_STRUCT")[1] + ENGINE_SOURCE,
                       include_dirs=[str(INCLUDE_DIR)],
                       extra_link_args=[str(pathlib.Path(__file__).parent.resolve()) + ENGINE_PATH])

with open(os.path.join(os.path.dirname(__file__), "ndpi.pack")) as ndpi_pack:
    ffi_builder.cdef(TYPES_DEF)
    ffi_builder.cdef(ndpi_pack.read().split("//CFFI.NDPI_PACKED_STRUCTURES")[1], packed=True)
    ffi_builder.cdef(NDPI_CDEF)
    ffi_builder.cdef(ENGINE_SOURCE)


if __name__ == "__main__":
    ffi_builder.compile(verbose=True)
