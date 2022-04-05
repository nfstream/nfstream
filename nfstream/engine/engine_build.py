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
import os

# Adapt PATH for temporary build directory output according to detected platform
USR_LOCAL = "usr/local"
if os.name != 'posix':
    RPATH = "mingw64"

USR = "usr"
if os.name != 'posix':
    RPATH = "mingw64"

TMP = "/tmp"
if os.name != 'posix':
    TMP = "D:/a/_temp/msys64/tmp"

# As cdef do not support ifdef yet we fix it by simple string replacement
SOCK_INCLUDES = """#include <unistd.h>\n#include <netinet/in.h>\n#include <sys/time.h>"""
if os.name != 'posix':
    SOCK_INCLUDES = """#include <winsock2.h>\n#include <process.h>\n#include <io.h>"""

ENGINE_INCLUDES = """
#include <stdlib.h>
""" + SOCK_INCLUDES + """
#include <math.h>
#include <stdint.h>
#include <string.h>
#include "ndpi_main.h"
#include "ndpi_typedefs.h"
#include "ndpi_api.h"
#include <pcap.h>
"""

with open("{tmp}/nfstream_build/lib_engine_cdefinitions.c".format(tmp=TMP)) as engine_cdef:
    ENGINE_CDEF = engine_cdef.read()

ENGINE_APIS = """
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

INCLUDE_DIRS = ["{tmp}/nfstream_build/{usr}/include/ndpi".format(usr=USR, tmp=TMP),
                "{tmp}/nfstream_build/{usr}/include".format(usr=USR_LOCAL, tmp=TMP)]
if os.name != 'posix':
    INCLUDE_DIRS.append("{tmp}/nfstream_build/npcap/Include".format(tmp=TMP))

EXTRALINK_ARGS = ["{tmp}/nfstream_build/{usr}/lib/libndpi.a".format(usr=USR, tmp=TMP),
                  "{tmp}/nfstream_build/{usr}/lib/libgcrypt.a".format(usr=USR_LOCAL, tmp=TMP),
                  "{tmp}/nfstream_build/{usr}/lib/libgpg-error.a".format(usr=USR_LOCAL, tmp=TMP)]

if os.name != 'posix':
    # FIXME: Need to check an env variable and if not defined, then use this hacky ci path.
    EXTRALINK_ARGS.append("D:/a/_temp/msys64/mingw64/lib/libws2_32.a")
else:
    EXTRALINK_ARGS.append("{tmp}/nfstream_build/{usr}/lib/libpcap.a".format(usr=USR_LOCAL, tmp=TMP))


def cdef_to_replace(cdef):
    to_rep = []
    cdef_list = cdef.split("static inline")
    for idx, sub_def in enumerate(cdef_list):
        end = sub_def.find("}")
        if end and idx:
            to_rep.append(sub_def[:end+1])
    to_rep.append("typedef __builtin_va_list __darwin_va_list;")
    to_rep.append("typedef __signed char int8_t;")
    return to_rep


with open("{tmp}/nfstream_build/ndpi_cdefinitions.h".format(tmp=TMP)) as ndpi_cdefs:
    NDPI_CDEF = ndpi_cdefs.read()
    for to_replace in cdef_to_replace(NDPI_CDEF):
        NDPI_CDEF = NDPI_CDEF.replace(to_replace, "")
    NDPI_MODULE_STRUCT_CDEF = NDPI_CDEF.split("//CFFI.NDPI_MODULE_STRUCT")[1]


with open("{tmp}/nfstream_build/ndpi_cdefinitions_packed.h".format(tmp=TMP)) as ndpi_cdefs_pack:
    NDPI_PACKED = ndpi_cdefs_pack.read()

NDPI_PACKED_STRUCTURES = NDPI_PACKED.split("//CFFI.NDPI_PACKED_STRUCTURES")[1]

ENGINE_SOURCE = ENGINE_INCLUDES + NDPI_MODULE_STRUCT_CDEF + ENGINE_CDEF

ffi_builder = FFI()
# IMPORTANT: on Windows, we do not bundle npcap as its license do not allow to.
# We link to it dynamically and ask the users to install it to enable live capture.
if os.name != 'posix':
    ffi_builder.set_source("_lib_engine",
                           ENGINE_SOURCE,
                           libraries=["wpcap"],
                           library_dirs=["{tmp}/nfstream_build/npcap/Lib".format(tmp=TMP)],
                           include_dirs=INCLUDE_DIRS,
                           extra_link_args=EXTRALINK_ARGS)
else:
    ffi_builder.set_source("_lib_engine",
                           ENGINE_SOURCE,
                           include_dirs=INCLUDE_DIRS,
                           extra_link_args=EXTRALINK_ARGS)


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
