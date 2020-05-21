"""
file: observer.py
This file is part of fipp.

Copyright (C) 2019-20 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from os.path import abspath, dirname, isfile
from psutil import net_if_addrs
import cffi
from collections import namedtuple

cc_observer_headers = """
struct pcap;
typedef struct pcap pcap_t;
typedef struct nf_packet {
  uint8_t consumable;
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
  uint16_t ip_size_from_header;
  uint8_t *ip_content;
  uint64_t hashval;
} nf_packet_t;

"""

cc_observer_apis = """
pcap_t *observer_open(const uint8_t * pcap_file, unsigned snaplen, int promisc, int to_ms, char *errbuf, 
                      char *errbuf_set, int mode);
int observer_configure(pcap_t * pcap_handle, char * bpf_filter);
int observer_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int nroots, int decode_tunnels);
void observer_close(pcap_t *);
"""


tcpflags = namedtuple('tcpflags', ['syn', 'cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'fin'])


def get_hash(proto, vlan_id, src_addr, dst_addr, sport, dport):
    return proto, vlan_id, min(src_addr, dst_addr), max(src_addr, dst_addr), min(sport, dport), max(sport, dport)


class NFPacket(object):
    def __init__(self, time, raw_size, ip_size, transport_size, payload_size,
                 nfhash, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id,
                 version, tcp_flags, ip_packet, root_idx):
        object.__setattr__(self, "time", time)
        object.__setattr__(self, "raw_size", raw_size)
        object.__setattr__(self, "ip_size", ip_size)
        object.__setattr__(self, "transport_size", transport_size)
        object.__setattr__(self, "payload_size", payload_size)
        object.__setattr__(self, "nfhash", nfhash)
        object.__setattr__(self, "src_ip", src_ip)
        object.__setattr__(self, "dst_ip", dst_ip)
        object.__setattr__(self, "src_port", src_port)
        object.__setattr__(self, "dst_port", dst_port)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "vlan_id", vlan_id)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "tcpflags", tcp_flags)
        object.__setattr__(self, "ip_packet", ip_packet)
        object.__setattr__(self, "root_idx", root_idx)
        object.__setattr__(self, "direction", 0)
        object.__setattr__(self, "closed", False)

    def __setattr__(self, *args):
        if self.closed:
            raise TypeError

    def __delattr__(self, *args):
        raise TypeError

    def __str__(self):
        """ String representation of flow """
        return str(namedtuple(type(self).__name__, self.__dict__.keys())(*self.__dict__.values()))

    def close(self, direction):
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "closed", True)


def validate_parameters(source, promisc, snaplen, bpf_filter, account_ip_padding_size, decode_tunnels):
    errors = ""
    if not isinstance(source, str):
        errors = errors + "\nPlease specify a pcap file path or a valid network interface name as source."
    if not isinstance(promisc, bool):
        errors = errors + "\nPlease specify a valid promisc parameter (possible values: True, False)."
    if not isinstance(snaplen, int) or (isinstance(snaplen, int) and snaplen <= 0):
        errors = errors + "\nPlease specify a valid snaplen parameter (positive integer)."
    if not isinstance(bpf_filter, str) and bpf_filter is not None:
        errors = errors + "\nPlease specify a valid bpf_filter string format."
    if not isinstance(account_ip_padding_size, bool):
        errors = errors + "\nPlease specify a valid account_ip_padding_size parameter (possible values: True, False)."
    if not isinstance(decode_tunnels, bool):
        errors = errors + "\nPlease specify a valid decode_tunnels parameter (possible values: True, False)."
    return errors


class NFObserver:
    """ NFObserver module main class """
    def __init__(self, source=None, snaplen=65535, promisc=True, to_ms=1, bpf_filter=None,
                 nroots=1, account_ip_padding_size=False, decode_tunnels=False):
        errors = validate_parameters(source, promisc, snaplen, bpf_filter, account_ip_padding_size,
                                     decode_tunnels)
        if errors != '':
            raise OSError(errors)
        self._ffi = cffi.FFI()
        self._lib = self._ffi.dlopen(dirname(abspath(__file__)) + '/observer_cc.so')
        self._ffi.cdef(cc_observer_headers)
        self._ffi.cdef(cc_observer_apis, override=True)

        if source in net_if_addrs().keys():
            self.mode = 1  # we found source in device interfaces and set mode to live.
        elif ".pcap" in source[-5:] and isfile(source):
            self.mode = 0  # .pcap extension and file exists, we set mode to offline
        else:
            raise OSError("Undefined source: {}. "
                          "Please specify a pcap file path or a valid network interface name.".format(source))

        if self.mode in [0, 1]:
            error_buffer = self._ffi.new("char []", 128)
            error_buffer_setter = self._ffi.new("char []", 128)
            handler = self._lib.observer_open(bytes(source, 'utf-8'), snaplen, int(promisc), to_ms,
                                              error_buffer, error_buffer_setter, self.mode)

            if handler == self._ffi.NULL:
                raise OSError(self._ffi.string(error_buffer).decode('ascii', 'ignore') + "\n" +
                              self._ffi.string(error_buffer_setter).decode('ascii', 'ignore'))
            else:
                # Once we have a valid handler, we move to BPF filtering configuration.
                if isinstance(bpf_filter, str):
                    rs = self._lib.observer_configure(handler, bytes(bpf_filter, 'utf-8'))
                    if rs > 0:
                        raise OSError("Failed to setup BPF filter: {}. Please use a valid one.".format(bpf_filter))
                elif bpf_filter is None:
                    pass
                else:
                    raise OSError("Please specify a pcap file path or a valid network interface name as source.")
                self.cap = handler
        self.nroots = nroots
        self.safety_time = 0
        self.account_ip_padding_size = account_ip_padding_size
        self.decode_tunnels = int(decode_tunnels)

    def next_nf_packet(self):
        nf_packet = self._ffi.new("struct nf_packet *")
        rv = self._lib.observer_next(self.cap, nf_packet, self.nroots, self.decode_tunnels)
        return rv, nf_packet

    def build_nf_packet(self, time, pkt):
        if self.account_ip_padding_size:
            rs_ip_size = pkt.ip_size
        else:
            rs_ip_size = pkt.ip_size_from_header
        src_ip = self._ffi.string(pkt.src_name).decode('utf-8', errors='ignore')
        dst_ip = self._ffi.string(pkt.dst_name).decode('utf-8', errors='ignore')
        return NFPacket(time=time,
                        raw_size=pkt.raw_size,
                        ip_size=rs_ip_size,
                        transport_size=pkt.transport_size,
                        payload_size=pkt.transport_size,
                        nfhash=get_hash(pkt.protocol, pkt.vlan_id, src_ip, dst_ip, pkt.src_port, pkt.dst_port),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=pkt.src_port,
                        dst_port=pkt.dst_port,
                        protocol=pkt.protocol,
                        vlan_id=pkt.vlan_id,
                        version=pkt.ip_version,
                        tcp_flags=tcpflags(syn=pkt.syn, cwr=pkt.cwr, ece=pkt.ece, urg=pkt.urg, ack=pkt.ack, psh=pkt.psh,
                                           rst=pkt.rst, fin=pkt.fin),
                        ip_packet=bytes(self._ffi.buffer(pkt.ip_content, pkt.ip_size)),
                        root_idx=pkt.hashval % self.nroots)

    def __iter__(self):
        try:
            while True:
                rv, pkt = self.next_nf_packet()
                if rv == -2:
                    raise KeyboardInterrupt
                elif rv == -1:
                    yield None
                elif rv == 0:
                    yield None
                else:
                    if rv == 1:
                        if pkt.consumable == 1:
                            if pkt.time >= self.safety_time:
                                self.safety_time = pkt.time
                                tm = pkt.time
                            else:
                                tm = self.safety_time
                            yield self.build_nf_packet(tm, pkt)
                        else:
                            yield None
        except KeyboardInterrupt:
            return

    def close(self):
        self._lib.observer_close(self.cap)
        self._ffi.dlclose(self._lib)

