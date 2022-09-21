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
import os


def cdef_to_replace(cdef):
    """ helper function that replaces unsupported definitions for cffi """
    to_rep = []
    cdef_list = cdef.split("static inline")
    for idx, sub_def in enumerate(cdef_list):
        end = sub_def.find("}")
        if end and idx:
            to_rep.append(sub_def[:end+1])
    to_rep.append("typedef __builtin_va_list __darwin_va_list;")
    to_rep.append("typedef __signed char int8_t;")
    return to_rep


def convert_path(p):
    """ dummy path converter """
    if os.name == 'posix':
        return p
    return p.replace("/", "\\")


# On Unix, we have our classic paths
ROOT = ""
USR = "usr"
USR_LOCAL = "usr/local"
if os.name != 'posix':  # Windows case, we must take into account msys2 path tree.
    MSYS2_PATH = os.getenv("MSYS2_PATH")  # If user have custom msys2 installation
    if MSYS2_PATH is None:  # User didn't set this path, we use default one
        os.environ["MSYS2_PATH"] = "C:/msys64"
    ROOT = os.getenv("MSYS2_PATH")
    USR = "mingw64"
    USR_LOCAL = "mingw64"


BUILD_SCRIPT_PATH = str(pathlib.Path(__file__).parent.resolve().joinpath("scripts").joinpath("build"))
# Patched path as it is passed to msys2 bash
ENGINE_PATH = str(pathlib.Path(__file__).parent.resolve()).replace("\\", "/")


if os.name != 'posix':  # Windows case
    os.environ["MSYSTEM"] = "MINGW64"
    BUILD_CMD = r"""'{}'""".format(str(BUILD_SCRIPT_PATH) + "_windows.sh")
    subprocess.check_call(["{msys}/usr/bin/bash".format(msys=ROOT).replace("/", "\\"),
                           "-l",
                           BUILD_CMD,
                           ENGINE_PATH],
                          shell=True)
else:  # Linux, MacOS
    subprocess.check_call([str(BUILD_SCRIPT_PATH) + ".sh"], shell=True)


INCLUDE_DIRS = ["{root}/tmp/nfstream_build/{usr}/include/ndpi".format(root=ROOT, usr=USR),
                "{root}/tmp/nfstream_build/{usr}/include".format(root=ROOT, usr=USR_LOCAL)]
EXTRALINK_ARGS = ["{root}/tmp/nfstream_build/lib/libndpi.a".format(root=ROOT)]

if os.name != 'posix':  # Windows
    INCLUDE_DIRS.append("{root}/tmp/nfstream_build/npcap/Include".format(root=ROOT))
    if os.path.exists(convert_path("{root}/{usr}/lib/libmingwex.a".format(root=ROOT, usr=USR))):
        EXTRALINK_ARGS.append("{root}/{usr}/lib/libmingwex.a".format(root=ROOT, usr=USR))
    else:  # best effort guess
        EXTRALINK_ARGS.append("{root}/{usr}/lib/libmingwex.a".format(root=ROOT, usr=USR+"/x86_64-w64-mingw32"))
    if os.path.exists(convert_path("{root}/{usr}/lib/libmsvcrt.a".format(root=ROOT, usr=USR))):
        EXTRALINK_ARGS.append("{root}/{usr}/lib/libmsvcrt.a".format(root=ROOT, usr=USR))
    else:  # best effort guess
        EXTRALINK_ARGS.append("{root}/{usr}/lib/libmsvcrt.a".format(root=ROOT, usr=USR+"/x86_64-w64-mingw32"))
    with open(convert_path("{root}/tmp/nfstream_build/gcc_version.in".format(root=ROOT))) as gcc_version_in:
        GCC_VERSION = gcc_version_in.read().split("\n")[0].split(")")[-1].strip()
    EXTRALINK_ARGS.append("{root}/{usr}/lib/gcc/x86_64-w64-mingw32/{version}/libgcc.a".format(root=ROOT,
                                                                                              usr=USR,
                                                                                              version=GCC_VERSION))
    # IMPORTANT: We link with wpcap.lib from downloaded SDK in order to not bundle npcap OEM binaries.
    # Consequently, the generated extension will still look for these binaries on the host machine.
    # Instructions on how to install npcap binaries are provided in README (Windows Note).
    EXTRALINK_ARGS.append("{root}/tmp/nfstream_build/npcap/Lib/x64/wpcap.lib".format(root=ROOT))
    # And finally socket stuff
    if os.path.exists(convert_path("{root}/{usr}/lib/libws2_32.a".format(root=ROOT, usr=USR))):
        EXTRALINK_ARGS.append("{root}/{usr}/lib/libws2_32.a".format(root=ROOT, usr=USR))
    else:  # best effort guess
        EXTRALINK_ARGS.append("{root}/usr/lib/w32api/libws2_32.a".format(root=ROOT))
else:
    EXTRALINK_ARGS.append("{root}/tmp/nfstream_build/{usr}/lib/libpcap.a".format(root=ROOT, usr=USR_LOCAL))

with open(convert_path("{root}/tmp/nfstream_build/lib_engine_cdefinitions.c".format(root=ROOT))) as engine_cdef:
    ENGINE_CDEF = engine_cdef.read()

with open(convert_path("{root}/tmp/nfstream_build/ndpi_cdefinitions.h".format(root=ROOT))) as ndpi_cdefs:
    NDPI_CDEF = ndpi_cdefs.read()
    for to_replace in cdef_to_replace(NDPI_CDEF):
        NDPI_CDEF = NDPI_CDEF.replace(to_replace, "")
    NDPI_MODULE_STRUCT_CDEF = NDPI_CDEF.split("//CFFI.NDPI_MODULE_STRUCT")[1]

with open(convert_path("{root}/tmp/nfstream_build/ndpi_cdefinitions_packed.h".format(root=ROOT))) as ndpi_cdefs_pack:
    NDPI_PACKED = ndpi_cdefs_pack.read()

NDPI_PACKED_STRUCTURES = NDPI_PACKED.split("//CFFI.NDPI_PACKED_STRUCTURES")[1]


# --------------------------------Engine Library Magic Code Generator --------------------------------------------------


# As cdef do not support if-def, yet we fix it by simple string replacement
SOCK_INCLUDES = """#include <unistd.h>\n#include <netinet/in.h>\n#include <sys/time.h>"""
if os.name != 'posix':
    SOCK_INCLUDES = """#include <winsock2.h>\n#include <process.h>\n#include <io.h>"""
ENGINE_INCLUDES = """
#include <stdlib.h>
""" + SOCK_INCLUDES + """
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <ndpi_api.h>
#include <pcap.h>
"""
ENGINE_SOURCE = ENGINE_INCLUDES + NDPI_MODULE_STRUCT_CDEF + ENGINE_CDEF
ENGINE_APIS = """
char * capture_get_interface(char * intf_name);
pcap_t * capture_open(const uint8_t * pcap_file, int mode, char * child_error);
int capture_activate(pcap_t * pcap_handle, int mode, char * child_error);
int capture_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int decode_tunnels, int n_roots, uint64_t root_idx,
                 int mode);
void capture_close(pcap_t * pcap_handle);
void capture_stats(pcap_t * pcap_handle, struct nf_stat *nf_statistics, unsigned mode);
int capture_set_fanout(pcap_t * pcap_handle, int mode, char * child_error, int group_id);
int capture_set_timeout(pcap_t * pcap_handle, int mode, char * child_error);
int capture_set_promisc(pcap_t * pcap_handle, int mode, char * child_error, int promisc);
int capture_set_snaplen(pcap_t * pcap_handle, int mode, char * child_error, unsigned snaplen);
int capture_set_filter(pcap_t * pcap_handle, char * bpf_filter, char * child_error);

struct ndpi_detection_module_struct *dissector_init(struct dissector_checker *checker);
void dissector_configure(struct ndpi_detection_module_struct *dissector);
void dissector_cleanup(struct ndpi_detection_module_struct *dissector);

struct nf_flow *meter_initialize_flow(struct nf_packet *packet, uint8_t accounting_mode, uint8_t statistics,
                                      uint8_t splt, uint8_t n_dissections,
                                      struct ndpi_detection_module_struct *dissector, uint8_t sync);
uint8_t meter_update_flow(struct nf_flow *flow, struct nf_packet *packet, uint64_t idle_timeout, uint64_t active_timeout,
                          uint8_t accounting_mode, uint8_t statistics, uint8_t splt, uint8_t n_dissections,
                          struct ndpi_detection_module_struct *dissector, uint8_t sync);
void meter_expire_flow(struct nf_flow *flow, uint8_t n_dissections, struct ndpi_detection_module_struct *dissector);
void meter_free_flow(struct nf_flow *flow, uint8_t n_dissections, uint8_t splt, uint8_t full);
const char *engine_lib_version(void);
const char *engine_lib_ndpi_version(void);
const char *engine_lib_pcap_version(void);
"""
ffi_builder = FFI()
ffi_builder.set_source("_lib_engine",
                       ENGINE_SOURCE,
                       include_dirs=[convert_path(d) for d in INCLUDE_DIRS],
                       extra_link_args=[convert_path(a) for a in EXTRALINK_ARGS])
ffi_builder.cdef("""
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
struct pcap;
typedef struct pcap pcap_t;
""")
ffi_builder.cdef(NDPI_PACKED_STRUCTURES, packed=True)
ffi_builder.cdef(NDPI_CDEF, override=True)
ffi_builder.cdef(ENGINE_CDEF.split("//CFFI_SHARED_STRUCTURES")[1])
ffi_builder.cdef(ENGINE_APIS)


if __name__ == "__main__":
    ffi_builder.compile(verbose=True)
