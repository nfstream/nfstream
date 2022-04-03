"""
------------------------------------------------------------------------------------------------------------------------
engine.py
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

from psutil import net_if_addrs
from _engine import ffi, lib


NPCAP_PATH = "C:\\Windows\\System32\\Npcap\\wpcap.dll"

NPCAP_HEADERS = """
struct pcap;
typedef struct pcap pcap_t;
struct bpf_insn;
struct bpf_program {
  unsigned int bf_len;
  struct bpf_insn *bf_insns;
};
struct pcap_addr {
  struct pcap_addr *next;
  struct sockaddr *addr;
  struct sockaddr *netmask;
  struct sockaddr *broadaddr;
  struct sockaddr *dstaddr;
};
typedef struct pcap_addr pcap_addr_t;
struct pcap_if {
  struct pcap_if *next;
  char *name;
  char *description;
  pcap_addr_t *addresses;
  int flags;
};
struct pcap_stat {
  unsigned int recv;
  unsigned int drop;
  unsigned int ifdrop;
};
typedef struct pcap_if pcap_if_t;
struct pcap_pkthdr {
  long tv_sec;
  long tv_usec;
  unsigned int caplen;
  unsigned int len;
};
"""

NPCAP_APIS = """
int pcap_findalldevs(pcap_if_t **, char *);
void pcap_freealldevs(pcap_if_t *);
pcap_t * capture_open(const uint8_t * pcap_file, int mode, char * child_error);
int pcap_set_promisc(pcap_t *, int);
int pcap_set_snaplen(pcap_t *, int);
int pcap_set_timeout(pcap_t *, int);
int pcap_activate(pcap_t *);
pcap_t *pcap_create(const char *, char *); 
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
int pcap_setfilter(pcap_t *, struct bpf_program *);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, unsigned int);
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
int pcap_datalink(pcap_t *);
void pcap_breakloop(pcap_t *);
void pcap_close(pcap_t *);
char *pcap_geterr(pcap_t *);
int pcap_stats(pcap_t *, struct pcap_stat *);
"""


# We declare here all headers and APIs of native nfstream, This will include:
#   - headers and APIs for capture stage (packet capture and processing).
#   - headers and APIs for nDPI (the dissection part).
#   - headers and APIs for Metering stage (flow intialization, update, expiration and cleaning)

# We group it in an "engine" initialized by meter as start in order to share the same ffi instance between stages.

# For windows platform, nfstream is based on npcap library. As npcap do not allow redistribution without having a valid
# redistribution licence, we cannot link it statically to the nfstream engine lib as we do for UNIX based system with
# libpcap.
# Consequently, our approach is as follows:
# - We still link statically nDPI and its dependencies to the engine lib.
# - For capture part (capture API), we move to a pure Python interface in ABI mode with the npcap dll
#   installed by the user.


def capture_open(ffi, npcap, pcap_file, mode, error_child):
    pcap_handle = ffi.NULL
    if mode == 0:
        pcap_handle = npcap.pcap_open_offline(pcap_file, error_child)
    if mode == 1:
        pcap_handle = npcap.pcap_create(pcap_file, error_child)
    return pcap_handle


def capture_set_timeout(npcap, pcap_handle, mode):
    set_timeout = 0
    if mode != 0:
        set_timeout = npcap.pcap_set_timeout(pcap_handle, 1000)
        if set_timeout != 0:
            npcap.pcap_close(pcap_handle)
    return set_timeout


def capture_set_promisc(npcap, pcap_handle, mode, promisc):
    set_promisc = 0
    if mode != 0:
        set_promisc = npcap.pcap_set_promisc(pcap_handle, promisc)
        if set_promisc != 0:
            npcap.pcap_close(pcap_handle)
    return set_promisc


def capture_set_snaplen(npcap, pcap_handle, mode, snaplen):
    set_snaplen = 0
    if mode != 0:
        set_snaplen = npcap.pcap_set_snaplen(pcap_handle, snaplen)
        if set_snaplen != 0:
            npcap.pcap_close(pcap_handle)
    return set_snaplen


def setup_capture_unix(ffi, lib, source, snaplen, promisc, mode, error_child, group_id):
    capture = lib.capture_open(bytes(source, 'utf-8'), mode, error_child)
    if capture == ffi.NULL:
        return
    fanout_set_failed = lib.capture_set_fanout(capture, mode, error_child, group_id)
    if fanout_set_failed:
        return
    timeout_set_failed = lib.capture_set_timeout(capture, mode, error_child)
    if timeout_set_failed:
        return
    promisc_set_failed = lib.capture_set_promisc(capture, mode, error_child, int(promisc))
    if promisc_set_failed:
        return
    snaplen_set_failed = lib.capture_set_snaplen(capture, mode, error_child, snaplen)
    if snaplen_set_failed:
        return
    return capture


def setup_capture_windows(ffi, npcap, source, snaplen, promisc, mode, error_child):
    capture = capture_open(ffi, npcap, bytes(source, 'utf-8'), mode, error_child)
    if capture == ffi.NULL:
        return
    timeout_set_failed = capture_set_timeout(npcap, capture, mode)
    if timeout_set_failed:
        ffi.memmove(error_child, b'Unable to set buffer timeout.', 256)
        return
    promisc_set_failed = capture_set_promisc(npcap, capture, mode, int(promisc))
    if promisc_set_failed:
        ffi.memmove(error_child, b'Unable to set promisc mode.', 256)
        return
    snaplen_set_failed = capture_set_snaplen(npcap, capture, mode, snaplen)
    if snaplen_set_failed:
        ffi.memmove(error_child, b'Unable to set snaplen.', 256)
        return
    return capture


def setup_capture(is_windows, ffi, lib, npcap, source, snaplen, promisc, mode, error_child, group_id):
    """ Setup capture """
    if is_windows:  # We move to pure Python API
        return setup_capture_windows(ffi, npcap, source, snaplen, promisc, mode, error_child)
    # We use APIs defined within the engine.
    return setup_capture_unix(ffi, lib, source, snaplen, promisc, mode, error_child, group_id)


def capture_set_filter(npcap, ffi, pcap_handle, bpf_filter, child_error):
    set_filter = 0
    if bpf_filter != ffi.NULL:
        fcode = ffi.new("struct bpf_program *")
        if npcap.pcap_compile(pcap_handle, fcode, bpf_filter, 1, 0xFFFFFF00) < 0:
            ffi.memmove(child_error, b'Unable to compile BPF filter.', 256)
            npcap.pcap_close(pcap_handle)
            set_filter = 1
        else:
            if npcap.pcap_setfilter(pcap_handle, fcode) < 0:
                ffi.memmove(child_error, b'Unable to compile BPF filter.', 256)
                npcap.pcap_close(pcap_handle)
                set_filter = 1
    return set_filter


def setup_filter_windows(npcap, ffi, capture, error_child, bpf_filter):
    """ Compile and setup BPF filter on Windows """
    if bpf_filter is not None:
        filter_set_failed = capture_set_filter(npcap, ffi, capture, bytes(bpf_filter, 'utf-8'), error_child)
        if filter_set_failed:
            return False
    return True


def setup_filter_unix(capture, lib, error_child, bpf_filter):
    """ Compile and setup BPF filter on Unix """
    if bpf_filter is not None:
        filter_set_failed = lib.capture_set_filter(capture, bytes(bpf_filter, 'utf-8'), error_child)
        if filter_set_failed:
            return False
    return True


def capture_activate(ffi, npcap, pcap_handle, mode, error_child):
    set_activate = 0
    if mode != 0:
        set_activate = npcap.pcap_activate(pcap_handle)
        if set_activate != 0:
            npcap.pcap_close(pcap_handle)
            ffi.memmove(error_child, b'Unable to activate source.', 256)
    return set_activate


def activate_capture_windows(npcap, ffi, capture, error_child, bpf_filter, mode):
    """ Capture activation function for Windows """
    activation_failed = capture_activate(ffi, npcap, capture, mode, error_child)
    if activation_failed:
        return False
    return setup_filter_windows(npcap, ffi, capture, error_child, bpf_filter)


def activate_capture_unix(capture, lib, error_child, bpf_filter, mode):
    """ Capture activation function for UNIX"""
    activation_failed = lib.capture_activate(capture, mode, error_child)
    if activation_failed:
        return False
    return setup_filter_unix(capture, lib, error_child, bpf_filter)


def activate_capture(is_windows, npcap, ffi, capture, lib, error_child, bpf_filter, mode):
    """ Capture activation function """
    if is_windows:
        return activate_capture_windows(npcap, ffi, capture, error_child, bpf_filter, mode)
    return activate_capture_unix(capture, lib, error_child, bpf_filter, mode)


def packet_process(npcap, lib, pcap_handle, hdr, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode):
    time = int(hdr.tv_sec * 1000 + hdr.tv_usec / (1000000 / 1000))
    rv_processor = lib.packet_process(npcap.pcap_datalink(pcap_handle), hdr.caplen, hdr.len, data,
                                      decode_tunnels, nf_pkt, n_roots, root_idx, mode, time)
    if (rv_processor == 0) or (rv_processor == 1):
        return rv_processor
    return 2


def capture_next(ffi, npcap, lib, pcap_handle, nf_pkt, decode_tunnels, n_roots, root_idx, mode):
    """ Get next packet information from pcap handle """
    phdr = ffi.new("struct pcap_pkthdr **", ffi.NULL)
    pdata = ffi.new("uint8_t **", ffi.NULL)
    rv_handle = npcap.pcap_next_ex(pcap_handle, phdr, ffi.cast("unsigned char **", pdata))
    hdr = phdr[0]
    data = pdata[0]
    if rv_handle == 1:
        return packet_process(npcap, lib, pcap_handle, hdr, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode)
    if rv_handle == 0:
        if hdr == ffi.NULL or data == ffi.NULL:
            return -1
        return packet_process(npcap, lib, pcap_handle, hdr, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode)
    if rv_handle == -2:
        return -2
    return -1


def capture_close(is_windows, npcap, lib, pcap_handle):
    """ Capture close function """
    if is_windows:
        npcap.pcap_breakloop(pcap_handle)
        npcap.pcap_close(pcap_handle)
    else:
        lib.capture_close(pcap_handle)


def setup_dissector(ffi, lib, n_dissections):
    """ Setup dissector according to n_dissections value """
    if n_dissections:  # Dissection activated
        # Check that headers and loaded library match and initiate dissector.
        checker = ffi.new("struct dissector_checker *")
        checker.flow_size = ffi.sizeof("struct ndpi_flow_struct")
        checker.flow_tcp_size = ffi.sizeof("struct ndpi_flow_tcp_struct")
        checker.flow_udp_size = ffi.sizeof("struct ndpi_flow_udp_struct")
        dissector = lib.dissector_init(checker)
        if dissector == ffi.NULL:
            return ffi.NULL
        # Configure it (activate bitmask to all protocols)
        lib.dissector_configure(dissector)
        return dissector
    return ffi.NULL


def capture_stats(ffi, npcap, pcap_handle, nf_statistics, mode):
    if mode == 0:
        return
    statistics = ffi.new("struct pcap_stat *")
    ret = npcap.pcap_stats(pcap_handle, statistics)
    if ret == 0:
        nf_statistics.received = statistics[0].recv
        nf_statistics.dropped = statistics[0].drop
        nf_statistics.dropped_by_interface = statistics[0].ifdrop
    else:
        print("Warning: Error while reading interface performance statistics.")
    return


def discover_interfaces():
    """ Interfaces discovery utility for windows """
    interfaces = {}
    ffi_t = cffi.FFI()
    try:
        npcap = ffi.dlopen(NPCAP_PATH)
    except OSError:
        return interfaces
    ffi_t.cdef(NPCAP_HEADERS)
    ffi_t.cdef(NPCAP_APIS)
    ppintf = ffi.new("pcap_if_t * *")
    errbuf = ffi.new("char []", 128)
    rv = npcap.pcap_findalldevs(ppintf, errbuf)
    if rv:
        return interfaces
    pintf = ppintf[0]
    tmp = pintf
    while tmp != ffi.NULL:
        name = ffi.string(tmp.name).decode('ascii', 'ignore')
        if tmp.description != ffi.NULL:
            interfaces[name] = ffi.string(tmp.description).decode('ascii', 'ignore')
        else:
            interfaces[name] = ""
        tmp = tmp.next
    npcap.pcap_freealldevs(pintf)
    ffi_t.dlclose(npcap)
    return interfaces


def is_interface(val, is_windows):
    """ Check if val is a valid interface name and return it if true else None """
    # On windows if the user give a description instead of network device name, we comply with it.
    if is_windows:
        interfaces_map = discover_interfaces()
    else:
        interfaces_map = dict.fromkeys(net_if_addrs().keys(), "")
    for k, v in interfaces_map.items():
        if val == k or val == v:
            return k
    return None


def create_engine(is_windows):
    """ engine creation function, return the loaded native nfstream engine and it's ffi interface"""
    npcap = None
    if is_windows:
        try:
            npcap = ffi.dlopen(NPCAP_PATH)
            ffi.cdef(NPCAP_HEADERS)
            ffi.cdef(NPCAP_APIS)
        except OSError:
            pass
    return ffi, lib, npcap
