#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
observer.py
Copyright (C) 2019-20 - NFStream Developers
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

from os.path import abspath, dirname, isfile
from collections import namedtuple
from psutil import net_if_addrs
import cffi

cc_observer_headers = """
struct pcap;
typedef struct pcap pcap_t;
typedef struct nf_packet {
  uint64_t time;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  uint16_t vlan_id;
  char src_name[48], dst_name[48];
  uint8_t ip_version;
  uint16_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1; /* TCP Flags */
  uint16_t raw_size;
  uint16_t ip_size;
  uint16_t transport_size;
  uint16_t payload_size;
  uint16_t ip_content_len;
  uint8_t *ip_content;
} nf_packet_t;

"""

cc_observer_apis = """
pcap_t *observer_open(const uint8_t * pcap_file, unsigned snaplen, int promisc, char *err_open,
                      char *err_set, int mode);
int observer_configure(pcap_t * pcap_handle, char * bpf_filter);
int observer_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int decode_tunnels, int n_roots, int root_idx);
void observer_close(pcap_t *);
"""


tcpflags = namedtuple('tcpflags', ['syn', 'cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'fin'])


class NFPacket(object):
    __slots__ = ["time", "raw_size", "ip_size", "transport_size", "payload_size", "nfhash", "src_ip", "dst_ip",
                 "src_port", "dst_port", "protocol", "vlan_id", "version", "tcpflags", "ip_packet", "direction",
                 "closed"]

    def __init__(self, pkt, ffi):
        src_ip = ffi.string(pkt.src_name).decode('utf-8', errors='ignore')
        dst_ip = ffi.string(pkt.dst_name).decode('utf-8', errors='ignore')
        self.time = pkt.time
        self.raw_size = pkt.raw_size
        self.ip_size = pkt.ip_size
        self.transport_size = pkt.transport_size
        self.payload_size = pkt.payload_size
        self.nfhash = pkt.protocol, \
                      pkt.vlan_id, \
                      min(src_ip, dst_ip), max(src_ip, dst_ip),\
                      min(pkt.src_port, pkt.dst_port), max(pkt.src_port, pkt.dst_port)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = pkt.src_port
        self.dst_port = pkt.dst_port
        self.protocol = pkt.protocol
        self.vlan_id = pkt.vlan_id
        self.version = pkt.ip_version
        self.tcpflags = tcpflags(syn=pkt.syn, cwr=pkt.cwr,
                                 ece=pkt.ece, urg=pkt.urg,
                                 ack=pkt.ack, psh=pkt.psh,
                                 rst=pkt.rst, fin=pkt.fin)
        self.ip_packet = bytes(ffi.buffer(pkt.ip_content, pkt.ip_content_len))
        self.direction = 0
        self.closed = False

    def __str__(self):
        return str(namedtuple(type(self).__name__, self.__dict__.keys())(*self.__dict__.values()))


def create_observer_context():
    ffi = cffi.FFI()
    lib = ffi.dlopen(dirname(abspath(__file__)) + '/observer_cc.so')
    ffi.cdef(cc_observer_headers)
    ffi.cdef(cc_observer_apis, override=True)
    return ffi, lib


def set_observer_mode(src, ffi, lib):
    if src in net_if_addrs().keys():
        return 1
    elif ".pcap" in src[-5:] and isfile(src):
        return 0
    else:
        ffi.dlclose(lib)
        raise OSError("Undefined source: {}. "
                      "Please specify a pcap file path or a valid network interface name.".format(src))


def open_observer(src, snaplen, mode, promisc, ffi, lib):
    err_open = ffi.new("char []", 128)
    err_set = ffi.new("char []", 128)
    handler = lib.observer_open(bytes(src, 'utf-8'), snaplen, int(promisc), err_open, err_set, mode)
    if handler == ffi.NULL:
        ffi.dlclose(lib)
        error_message = "{}\n{}".format(ffi.string(err_open).decode('ascii', 'ignore'),
                                        ffi.string(err_set).decode('ascii', 'ignore'))
        raise OSError(error_message)
    return handler


def configure_observer(handler, bpf_filter, ffi, lib):
    if bpf_filter is not None:
        # On a valid handler, we set BPF filtering if defined.
        rs = lib.observer_configure(handler, bytes(bpf_filter, 'utf-8'))
        if rs > 0:
            lib.observer_close(handler)
            ffi.dlclose(lib)
            if rs == 1:
                raise OSError("Failed to compile BPF filter.")
            else:
                raise OSError("Failed to set BPF filter.")
    return handler


def validate_observer_args(source, promisc, snaplen, bpf_filter, decode_tunnels):
    errors = ""
    if not isinstance(source, str):
        errors = errors + "\nPlease specify a pcap file path or a valid network interface name as source."
    if not isinstance(promisc, bool):
        errors = errors + "\nPlease specify a valid promisc parameter (possible values: True, False)."
    if not isinstance(snaplen, int) or (isinstance(snaplen, int) and snaplen <= 0):
        errors = errors + "\nPlease specify a valid snaplen parameter (positive integer)."
    if not isinstance(bpf_filter, str) and bpf_filter is not None:
        errors = errors + "\nPlease specify a valid bpf_filter format."
    if not isinstance(decode_tunnels, bool):
        errors = errors + "\nPlease specify a valid decode_tunnels parameter (possible values: True, False)."
    if errors != "":
        raise OSError(errors)


class NFObserver(object):
    """ NFObserver module main class """
    __slots__ = ["_cap", "_lib", "_ffi", "_mode", "_decode_tunnels", "_n_roots", "_root_idx"]

    def __init__(self, source=None, snaplen=65535, promisc=True, bpf_filter=None,
                 decode_tunnels=False, n_roots=1, root_idx=0):
        validate_observer_args(source, promisc, snaplen, bpf_filter, decode_tunnels)
        observer_ffi, observer_lib = create_observer_context()
        observer_mode = set_observer_mode(source, observer_ffi, observer_lib)
        cap = open_observer(source, snaplen, observer_mode, promisc, observer_ffi, observer_lib)
        cap = configure_observer(cap, bpf_filter, observer_ffi, observer_lib)
        self._cap = cap
        self._ffi = observer_ffi
        self._lib = observer_lib
        self._mode = observer_mode
        self._decode_tunnels = decode_tunnels
        self._n_roots = n_roots
        self._root_idx = root_idx

    def __iter__(self):
        # faster as we make intensive access to these members.
        observer_ffi = self._ffi
        observer_lib = self._lib
        observer_cap = self._cap
        decode_tunnels = self._decode_tunnels
        observer_mode = self._mode
        n_roots = self._n_roots
        root_idx = self._root_idx
        observer_time = 0

        try:
            while True:
                nf_packet = observer_ffi.new("struct nf_packet *")
                ret = observer_lib.observer_next(observer_cap, nf_packet, decode_tunnels, n_roots, root_idx)
                if ret > 0:  # Valid, must be processed by meter
                    time = nf_packet.time
                    if time > observer_time:
                        observer_time = time
                    else:
                        time = observer_time
                    if ret == 1:
                        yield 1, time, NFPacket(nf_packet, observer_ffi)
                    elif ret == 2:  # Time ticker (Valid but do not match our id)
                        yield 0, time, None
                    else:
                        if observer_mode == 1:
                            yield 0, time, None  # Time ticker (timeout on live buffer)
                        else:
                            pass  # Should never happen
                elif ret == 0:  # Ignored
                    pass
                elif ret == -1:  # Read error
                    pass
                else:  # End of file
                    raise KeyboardInterrupt
        except KeyboardInterrupt:
            return

    def close(self):
        self._lib.observer_close(self._cap)
        self._ffi.dlclose(self._lib)

