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
import pathlib
import os
import re

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

ffi_builder = FFI()

with open(str(os.path.join(os.path.dirname(__file__), "ndpi.cdef")).replace("\\", "/")) as ndpi_cdef:
    with open(os.path.join(os.path.dirname(__file__), "engine_cc.h")) as engine_cc_h:
        ENGINE_SOURCE = PCAP_INCLUDES
        NDPI_CDEF = re.sub('static inline[^>]+}', '', ndpi_cdef.read())
        NDPI_CDEF = NDPI_CDEF.replace(
            "typedef __builtin_va_list __darwin_va_list;", "")\
            .replace(
            "typedef __signed char int8_t;", "")
        ENGINE_SOURCE += "".join(engine_cc_h.read().split("//CFFI_ENGINE_EXCLUDE")[2::2])

ffi_builder.set_source("_engine",
                       NDPI_INCLUDES + NDPI_CDEF.split("//CFFI.NDPI_MODULE_STRUCT")[1] + ENGINE_SOURCE,
                       include_dirs=[str(INCLUDE_DIR)],
                       extra_link_args=[str(pathlib.Path(__file__).parent.resolve()) + ENGINE_PATH])

with open(str(os.path.join(os.path.dirname(__file__), "ndpi.pack")).replace("\\", "/")) as ndpi_pack:
    ffi_builder.cdef(TYPES_DEF)
    ffi_builder.cdef(ndpi_pack.read().split("//CFFI.NDPI_PACKED_STRUCTURES")[1], packed=True)
    ffi_builder.cdef(NDPI_CDEF, override=True)
    ffi_builder.cdef(ENGINE_SOURCE)


if __name__ == "__main__":
    ffi_builder.compile(verbose=True)
