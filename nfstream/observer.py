#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: observer.py
This file is part of nfstream.

Copyright (C) 2019-20 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""
from .ndpi import cc_ndpi_network_headers
from os.path import abspath, dirname
from collections import namedtuple
from socket import ntohs, ntohl
from enum import Enum, IntEnum
from threading import Lock
from select import select
from cffi import FFI
import os.path
import sys

cc_libpcap_structure = """
struct pcap;

typedef struct pcap pcap_t;

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

typedef struct pcap_if pcap_if_t;

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct pcap_pkthdr {
    struct timeval ts;
    unsigned int caplen;
    unsigned int len;
};
"""

cc_libpcap_apis = """
pcap_t *pcap_create(const char *, char *); 
pcap_t *pcap_open_live(const char *, int, int, int, char *);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
int pcap_datalink(pcap_t *);
int pcap_setnonblock(pcap_t *, int, char *); 
int pcap_getnonblock(pcap_t *, char *); 
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
void pcap_close(pcap_t *);
int pcap_get_selectable_fd(pcap_t *);
char *pcap_geterr(pcap_t *);
char *pcap_lib_version();
void pcap_freealldevs(pcap_if_t *);
int pcap_findalldevs(pcap_if_t **, char *);
int pcap_snapshot(pcap_t *);
"""

TICK_RESOLUTION = 1000


PcapInterface = namedtuple('PcapInterface', ['name', 'internal_name', 'description', 'isloop', 'isup', 'isrunning'])
PcapPacket = namedtuple('PcapPacket', ['timestamp', 'capture_length', 'length', 'raw'])
PcapDev = namedtuple('PcapDev', ['dlt', 'nonblock', 'snaplen', 'version', 'pcap'])
tcpflags = namedtuple('tcpflags', ['syn', 'cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'fin'])


class NFPacket(object):
    def __init__(self, time, raw_size, ip_size, transport_size, payload_size,
                 nfhash, ip_src, ip_dst, src_port, dst_port, protocol, vlan_id,
                 version, tcp_flags, ip_packet, root_idx):
        object.__setattr__(self, "time", time)
        object.__setattr__(self, "raw_size", raw_size)
        object.__setattr__(self, "ip_size", ip_size)
        object.__setattr__(self, "transport_size", transport_size)
        object.__setattr__(self, "payload_size", payload_size)
        object.__setattr__(self, "nfhash", nfhash)
        object.__setattr__(self, "ip_src", ip_src)
        object.__setattr__(self, "ip_dst", ip_dst)
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

    def close(self, direction):
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "closed", True)


class PcapException(Exception):
    pass


class Dlt(Enum):
    DLT_NULL = 0
    DLT_EN10MB = 1
    DLT_EN3MB = 2
    DLT_AX25 = 3
    DLT_PRONET = 4
    DLT_CHAOS = 5
    DLT_IEEE802 = 6
    DLT_ARCNET = 7
    DLT_SLIP = 8
    DLT_PPP = 9
    DLT_FDDI = 10
    DLT_PPP_SERIAL = 50
    DLT_RAW = 12
    DLT_C_HDLC = 104
    DLT_LINUX_SLL = 113
    DLT_IEEE802_11_RADIO = 127


class PcapDirection(IntEnum):
    InOut = 0
    In = 1
    Out = 2


class PcapTstampType(IntEnum):
    Host = 0
    HostLowPrec = 1
    HostHighPrec = 2
    Adapter = 3
    AdapterUnsync = 4


class PcapTstampPrecision(IntEnum):
    Micro = 0
    Nano = 1


class PcapWarning(IntEnum):
    Generic = 1
    PromiscNotSupported = 2
    TstampTypeNotSupported = 3


def fcf_type(fc):
    return (fc >> 2) & 0x3


def fcf_to_ds(fc):
    return fc & 0x0100


def fcf_from_ds(fc):
    return fc & 0x0200


def get_flags(d, p):
    if p == 6 and d is not None:
        return tcpflags(syn=int(d.syn),
                        cwr=int(d.cwr),
                        ece=int(d.ece),
                        urg=int(d.urg),
                        ack=int(d.ack),
                        psh=int(d.psh),
                        rst=int(d.rst),
                        fin=int(d.fin))
    else:
        return tcpflags(syn=0,
                        cwr=0,
                        ece=0,
                        urg=0,
                        ack=0,
                        psh=0,
                        rst=0,
                        fin=0)


def get_hash(proto, vlan_id, src_addr, dst_addr, sport, dport):
    return proto, vlan_id, min(src_addr, dst_addr), max(src_addr, dst_addr), min(sport, dport), max(sport, dport)


def get_pkt_info(time, ffi, version, vlan_id, iph, iph6, ipsize, l4_packet_len, rawsize, nroots,
                 account_ip_padding_size):
    if version == 4:
        if ipsize < 20:
            return None
        if ((iph.ihl * 4) > ipsize) or (ipsize < ntohs(iph.tot_len)):
            return None
        l4_offset = iph.ihl * 4
        l3 = ffi.cast('uint8_t *', iph)
    else:
        l4_offset = ffi.sizeof('struct ndpi_ipv6hdr')
        if ffi.sizeof('struct ndpi_ipv6hdr') > ipsize:
            return None
        l3 = ffi.cast('uint8_t *', iph6)
    if ipsize < (l4_offset + l4_packet_len):
        return None
    proto = iph.protocol
    l4 = ffi.cast('uint8_t *', l3) + l4_offset
    if proto == 6 and l4_packet_len >= ffi.sizeof('struct ndpi_tcphdr'):  # TCP
        tcph = ffi.cast('struct ndpi_tcphdr *', l4)
        sport = int(ntohs(tcph.source))
        dport = int(ntohs(tcph.dest))
        payload_len = max(0, l4_packet_len - (4*tcph.doff))
        l4_data_len = l4_packet_len - ffi.sizeof('struct ndpi_tcphdr')
        flags = get_flags(tcph, proto)
    elif proto == 17 and l4_packet_len >= ffi.sizeof('struct ndpi_udphdr'):  # UDP
        udph = ffi.cast('struct ndpi_udphdr *', l4)
        sport = int(ntohs(udph.source))
        dport = int(ntohs(udph.dest))
        if l4_packet_len > ffi.sizeof('struct ndpi_udphdr'):
            payload_len = l4_packet_len - ffi.sizeof('struct ndpi_udphdr')
        else:
            payload_len = 0
        l4_data_len = l4_packet_len - ffi.sizeof('struct ndpi_udphdr')
        flags = get_flags(None, proto)
    elif proto == 1:  # ICMP
        if l4_packet_len > ffi.sizeof('struct ndpi_icmphdr'):
            payload_len = l4_packet_len - ffi.sizeof('struct ndpi_icmphdr')
        else:
            payload_len = 0
        l4_data_len = l4_packet_len - ffi.sizeof('struct ndpi_icmphdr')
        sport = 0
        dport = 0
        flags = get_flags(None, proto)
    elif proto == 58:  # ICMPV6
        if l4_packet_len > ffi.sizeof('struct ndpi_icmp6hdr'):
            payload_len = l4_packet_len - ffi.sizeof('struct ndpi_icmp6hdr')
        else:
            payload_len = 0
        l4_data_len = l4_packet_len - ffi.sizeof('struct ndpi_icmp6hdr')
        sport = 0
        dport = 0
        flags = get_flags(None, proto)
    else:  # Non TCP/UDP/ICMP/ICMPV6
        sport = 0
        dport = 0
        l4_data_len = 0
        flags = get_flags(None, proto)
        payload_len = 0

    if version == 4:
        ipcontent = iph
        src_addr = ntohl(iph.saddr)
        dst_addr = ntohl(iph.daddr)
    else:
        ipcontent = iph6
        src_addr = ntohl(iph6.ip6_src.u6_addr.u6_addr32[0]) << 96 | \
                   ntohl(iph6.ip6_src.u6_addr.u6_addr32[1]) << 64 | \
                   ntohl(iph6.ip6_src.u6_addr.u6_addr32[2]) << 32 | \
                   ntohl(iph6.ip6_src.u6_addr.u6_addr32[3])
        dst_addr = ntohl(iph6.ip6_dst.u6_addr.u6_addr32[0]) << 96 | \
                   ntohl(iph6.ip6_dst.u6_addr.u6_addr32[1]) << 64 | \
                   ntohl(iph6.ip6_dst.u6_addr.u6_addr32[2]) << 32 | \
                   ntohl(iph6.ip6_dst.u6_addr.u6_addr32[3])

    hashval = proto + vlan_id + src_addr + dst_addr + sport + dport

    if account_ip_padding_size:
        reported_ip_size = ipsize
    else:
        reported_ip_size = ntohs(iph.tot_len)

    return NFPacket(time=time, raw_size=rawsize, ip_size=reported_ip_size, transport_size=l4_data_len,
                    payload_size=payload_len, nfhash=get_hash(proto, vlan_id, src_addr, dst_addr, sport, dport),
                    ip_src=src_addr, ip_dst=dst_addr, src_port=sport, dst_port=dport, protocol=proto, vlan_id=vlan_id,
                    version=version, tcp_flags=flags, ip_packet=bytes(ffi.buffer(ipcontent, ipsize)),
                    root_idx=hashval % nroots)


def get_pkt_info6(time, ffi, vlan_id, iph6, ipsize, rawsize, nroots, account_ip_padding_size):
    iph = ffi.new("struct ndpi_iphdr *")

    iph.version = 4
    iph.tot_len = iph6.ip6_hdr.ip6_un1_plen
    proto = iph6.ip6_hdr.ip6_un1_nxt
    ret = handle_ipv6_extension_headers(ffi.cast('uint8_t *', iph6) + ffi.sizeof('struct ndpi_ipv6hdr'),
                                        ntohs(iph6.ip6_hdr.ip6_un1_plen),
                                        iph6.ip6_hdr.ip6_un1_nxt)
    if ret[0] != 0:
        proto = ret[1]
    iph.protocol = proto
    return get_pkt_info(time, ffi, 6, vlan_id, iph, iph6, ipsize, ntohs(iph6.ip6_hdr.ip6_un1_plen), rawsize, nroots,
                        account_ip_padding_size)


def process_packet(ffi, time, vlan_id, iph, iph6, ipsize, rawsize, nroots, account_ip_padding_size):
    if iph6 == ffi.NULL:
        l4_pkt_len = ntohs(iph.tot_len) - (iph.ihl * 4)
        return get_pkt_info(time, ffi, 4, vlan_id, iph, ffi.NULL, ipsize, l4_pkt_len, rawsize, nroots,
                            account_ip_padding_size)
    else:
        return get_pkt_info6(time, ffi, vlan_id, iph6, ipsize, rawsize, nroots,
                             account_ip_padding_size)


def handle_ipv6_extension_headers(l4, l4_len, nxt):
    """ handle_ipv6_extension_headers: handle extension headers in IPv6 packets, ret: 0 for success, 1 upon failure """
    transport_layer = l4
    transport_layer_len = l4_len
    nxt_hdr = nxt
    while (nxt_hdr == 0 or
           nxt_hdr == 0 or
           nxt_hdr == 0 or
           nxt_hdr == 0 or
           nxt_hdr == 0 or
           nxt_hdr == 0):
        if nxt_hdr == 59:  # no next header
            return 1, nxt_hdr
        if nxt_hdr == 44:  # fragment extension header has fixed size of 8 bytes
            # and the first byte is the next header type
            if transport_layer_len < 8:
                return 1, nxt_hdr
            nxt_hdr = transport_layer[0]
            transport_layer_len -= 8
            transport_layer += 8
        # the other extension headers have one byte for the next header type and one byte for the *
        # extension header length in 8 byte steps minus the first 8 bytes
        if transport_layer_len < 2:
            return 1, nxt_hdr
        ehdr_len = transport_layer[1]
        ehdr_len *= 8
        ehdr_len += 8
        if transport_layer_len < ehdr_len:
            return 1, nxt_hdr
        nxt_hdr = transport_layer[0]
        transport_layer_len -= ehdr_len
        transport_layer += ehdr_len
    return 0, 0


class _PcapFfi(object):
    """ This class represents the low-level interface to the libpcap library. It encapsulates all the cffi calls
        and C/Python conversions, as well as translation of errors and error codes to PcapExceptions.  It is intended
        to be used as a singleton class through the PcapDumper and PcapLiveDevice classes, below. """
    _instance = None
    __slots__ = ['_ffi', '_libpcap', '_interfaces', '_windows']

    def __init__(self):
        """ Assumption: this class is instantiated once in the main thread before any other threads have a chance
            to try instantiating it. """
        if _PcapFfi._instance:
            raise Exception("Can't initialize this class more than once!")

        _PcapFfi._instance = self
        self._windows = False
        self._ffi = FFI()
        self._ffi.cdef(cc_ndpi_network_headers, override=True, packed=True)
        if "win" in sys.platform[:3]:
            raise PcapException('Windows OS is not currently supported.')
        elif sys.platform == 'darwin':
            self._ffi.cdef(cc_libpcap_structure, override=True)
            libname = '/libs/libpcap.so'
        else:
            self._ffi.cdef(cc_libpcap_structure, override=True)
            libname = '/libs/libpcap.so'
        try:
            self._ffi.cdef(cc_libpcap_apis, override=True)
            self._libpcap = self._ffi.dlopen(dirname(abspath(__file__)) + libname)
        except Exception as e:
            raise PcapException("Error opening libpcap: {}".format(e))

        self._interfaces = []
        self.discoverdevs()

    @staticmethod
    def instance():
        if not _PcapFfi._instance:
            _PcapFfi._instance = _PcapFfi()
        return _PcapFfi._instance

    @property
    def version(self):
        return self._ffi.string(self._libpcap.pcap_lib_version())

    def discoverdevs(self):
        """ Find all the pcap-eligible devices on the local system """
        if len(self._interfaces):
            raise PcapException("Device discovery should only be done once.")

        ppintf = self._ffi.new("pcap_if_t * *")
        errbuf = self._ffi.new("char []", 128)
        rv = self._libpcap.pcap_findalldevs(ppintf, errbuf)
        if rv:
            raise PcapException("pcap_findalldevs returned failure: {}".format(self._ffi.string(errbuf)))
        pintf = ppintf[0]
        tmp = pintf
        pindex = 0
        while tmp != self._ffi.NULL:
            xname = self._ffi.string(tmp.name)  # "internal name"; still stored as bytes object
            xname = xname.decode('ascii', 'ignore')

            if self._windows:
                ext_name = "port{}".format(pindex)
            else:
                ext_name = xname
            pindex += 1

            if tmp.description == self._ffi.NULL:
                xdesc = ext_name
            else:
                xdesc = self._ffi.string(tmp.description)
                xdesc = xdesc.decode('ascii', 'ignore')

            # NB: on WinPcap, only loop flag is set
            isloop = (tmp.flags & 0x1) == 0x1
            isup = (tmp.flags & 0x2) == 0x2
            isrunning = (tmp.flags & 0x4) == 0x4
            xif = PcapInterface(ext_name, xname, xdesc, isloop, isup, isrunning)
            self._interfaces.append(xif)

            tmp = tmp.next
        self._libpcap.pcap_freealldevs(pintf)

    @property
    def devices(self):
        return self._interfaces

    @property
    def lib(self):
        return self._libpcap

    @property
    def ffi(self):
        return self._ffi

    def _parse_packet(self, xdev, header, packet, nroots, account_ip_padding_size):
        # MPLS header
        mpls = self._ffi.new("union mpls *")
        # IP header
        iph = self._ffi.new("struct ndpi_iphdr *")
        # IPv6 header
        iph6 = self._ffi.new("struct ndpi_ipv6hdr *")
        # lengths and offsets
        eth_offset, ether_type, wifi_len, pyld_eth_len, ip_offset, frag_off, vlan_id = 0, 0, 0, 0, 0, 0, 0
        time = (header.ts.tv_sec * TICK_RESOLUTION) + (header.ts.tv_usec / (1000000 / TICK_RESOLUTION))
        dlt = self._libpcap.pcap_datalink(xdev)
        datalink_check = True
        while datalink_check:
            datalink_check = False
            if header.caplen < (40 + eth_offset):
                return None  # too short
            if Dlt(dlt) == Dlt.DLT_NULL:
                tmp_dlt_null = self._ffi.cast('struct ptr_uint32 *', packet + eth_offset)
                if int(ntohs(tmp_dlt_null.value)) == 2:
                    ether_type = 0x0800
                else:
                    ether_type = 0x86dd
                ip_offset = 4 + eth_offset
            elif (Dlt(dlt) == Dlt.DLT_C_HDLC) or (Dlt(dlt) == Dlt.DLT_PPP) or Dlt(dlt) == Dlt.DLT_PPP_SERIAL:
                chdlc = self._ffi.cast('struct ndpi_chdlc *', packet + eth_offset)
                ip_offset = self._ffi.sizeof('struct ndpi_chdlc')
                ether_type = ntohs(chdlc.proto_code)
            elif Dlt(dlt) == Dlt.DLT_EN10MB:  # IEEE 802.3 Ethernet - 1 */
                ethernet = self._ffi.cast('struct ndpi_ethhdr *', packet + eth_offset)
                ip_offset = self._ffi.sizeof('struct ndpi_ethhdr') + eth_offset
                check = ntohs(ethernet.h_proto)
                if check <= 1500:
                    pyld_eth_len = check
                elif check >= 1536:
                    ether_type = check
                if pyld_eth_len != 0:
                    llc = self._ffi.cast('struct ndpi_llc_header_snap *', packet + ip_offset)
                    if (llc.dsap == 0xaa) or (llc.ssap == 0xaa):  # check for LLC layer with SNAP ext
                        ether_type = llc.snap.proto_ID
                        ip_offset += 8
                    elif (llc.dsap == 0x42) or (llc.ssap == 0x42):  # No SNAP ext
                        return None
            elif Dlt(dlt) == Dlt.DLT_LINUX_SLL:  # Linux Cooked Capture - 113
                ether_type = (packet[eth_offset + 14] << 8) + packet[eth_offset + 15]
                ip_offset = 16 + eth_offset
            elif Dlt(dlt) == Dlt.DLT_IEEE802_11_RADIO:  # Radiotap link-layer - 127
                radiotap = self._ffi.cast('struct ndpi_radiotap_header *', packet + eth_offset)
                radio_len = radiotap.len
                if (radiotap.flags & 0x50) == 0x50:  # Check Bad FCS presence
                    return None
                if header.caplen < (eth_offset + radio_len + self._ffi.sizeof('struct ndpi_wifi_header')):
                    return None
                # Calculate 802.11 header length(variable)
                wifi = self._ffi.cast('struct ndpi_wifi_header *', packet + (eth_offset + radio_len))
                fc = wifi.fc
                # Check wifi data presence
                if fcf_type(fc) == 0x2:
                    if (fcf_to_ds(fc) and fcf_from_ds(fc) == 0x0) or (fcf_to_ds(fc) == 0x0 and fcf_from_ds(fc)):
                        wifi_len = 26  # + 4 byte fcs
                # Check ether_type from LLC
                llc = self._ffi.cast('struct ndpi_llc_header_snap *', packet + (eth_offset + wifi_len + radio_len))
                if llc.dsap == 0xaa:
                    ether_type = ntohs(llc.snap.proto_ID)
                # Set IP header offset
                ip_offset = wifi_len + radio_len + self._ffi.sizeof('struct ndpi_llc_header_snap') + eth_offset
            elif Dlt(dlt) == Dlt.DLT_RAW:
                ip_offset, eth_offset = 0, 0
            else:
                return None

            ether_type_check = True
            while ether_type_check:
                ether_type_check = False
                if ether_type == 0x8100:
                    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF
                    ether_type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3]
                    ip_offset += 4
                    while ether_type == 0x8100 and self._ffi.cast('unsigned', ip_offset) < header.caplen:
                        # Double tagging for 802.1Q
                        vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF
                        ether_type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3]
                        ip_offset += 4
                    ether_type_check = True
                elif (ether_type == 0x8847) or (ether_type == 0x8848):
                    tmp_u32 = self._ffi.cast('struct ptr_uint32 *', packet + ip_offset)
                    mpls.u32 = int(ntohl(tmp_u32.value))
                    ether_type = 0x0800
                    ip_offset += 4
                    while not mpls.mpls.s:
                        tmp_u32_loop = self._ffi.cast('struct ptr_uint32 *', packet + ip_offset)
                        mpls.u32 = int(ntohl(tmp_u32_loop.value))
                        ip_offset += 4
                    ether_type_check = True
                elif ether_type == 0x8864:
                    ether_type = 0x0800
                    ip_offset += 8
                    ether_type_check = True
                else:
                    pass

            ip_check = True
            while ip_check:
                ip_check = False
                if header.caplen < (ip_offset + self._ffi.sizeof('struct ndpi_iphdr')):
                    return None  # too short for next IP header
                iph = self._ffi.cast('struct ndpi_iphdr *', packet + ip_offset)
                if (ether_type == 0x0800) and (header.caplen >= ip_offset):  # work on Ethernet packets that contain IP
                    frag_off = ntohs(iph.frag_off)
                    if header.caplen < header.len:
                        print("WARNING: packet capture size is smaller than packet size (header.caplen < header.len).")
                if iph.version == 4:
                    ip_len = iph.ihl * 4
                    iph6 = self._ffi.NULL
                    if iph.protocol == 41:  # IPPROTO_IPV6
                        ip_offset += ip_len
                        if ip_len > 0:
                            ip_check = True
                    if (frag_off & 0x1FFF) != 0:
                        return None

                elif iph.version == 6:
                    if header.caplen < (ip_offset + self._ffi.sizeof('struct ndpi_ipv6hdr')):
                        return None  # too short for IPv6 header
                    iph6 = self._ffi.cast('struct ndpi_ipv6hdr *', packet + ip_offset)
                    ip_len = ntohs(iph6.ip6_hdr.ip6_un1_plen)
                    if header.caplen < (ip_offset +
                                        self._ffi.sizeof('struct ndpi_ipv6hdr') +
                                        ntohs(iph6.ip6_hdr.ip6_un1_plen)):
                        return None  # too short for IPv6 payload
                    if handle_ipv6_extension_headers(self._ffi.cast('uint8_t *', iph6) +
                                                     self._ffi.sizeof('struct ndpi_ipv6hdr'),
                                                     ip_len,
                                                     iph6.ip6_hdr.ip6_un1_nxt)[0] != 0:
                        return None
                    iph = self._ffi.NULL
                else:
                    return None

        return process_packet(self._ffi, time, vlan_id, iph, iph6, header.caplen - ip_offset, header.caplen,
                              nroots, account_ip_padding_size)

    def _recv_packet(self, xdev, nroots=1, account_ip_padding_size=False):
        phdr = self._ffi.new("struct pcap_pkthdr **")
        pdata = self._ffi.new("unsigned char **")
        rv = self._libpcap.pcap_next_ex(xdev, phdr, pdata)
        if rv == 1:
            return self._parse_packet(xdev, phdr[0], pdata[0], nroots, account_ip_padding_size)
        elif rv == 0: # timeout; nothing to return
            return 0
        elif rv == -1:  # error on receive; raise an exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xdev))
            raise PcapException("Error receiving packet: {}".format(s))
        elif rv == -2:  # reading from savefile, but none left
            return -2


def pcap_devices():
    return _PcapFfi.instance().devices


class PcapReader(object):
    """ Class the represents a reader of an existing pcap capture file. """
    __slots__ = ['_ffi', '_libpcap', '_base', '_pcapdev', '_user_callback']

    def __init__(self, filename):
        self._base = _PcapFfi.instance()
        self._ffi = self._base.ffi
        self._libpcap = self._base.lib
        self._user_callback = None

        errbuf = self._ffi.new("char []", 128)
        pcap = self._libpcap.pcap_open_offline(bytes(filename, 'utf-8'), errbuf)
        if pcap == self._ffi.NULL:
            raise PcapException("Failed to open pcap file for reading: {}: {}".format(filename,
                                                                                      self._ffi.string(errbuf)))
        dl = self._libpcap.pcap_datalink(pcap)
        try:
            dl = Dlt(dl)
        except ValueError as e:
            raise PcapException("Don't know how to handle datalink type {}".format(dl))
        self._pcapdev = PcapDev(dl, 0, 0, _PcapFfi.instance().version, pcap)

    def close(self):
        self._libpcap.pcap_close(self._pcapdev.pcap)

    def recv_packet(self, nroots=1, account_ip_padding_size=False):
        return self._base._recv_packet(self._pcapdev.pcap, nroots, account_ip_padding_size)


class PcapLiveDevice(object):
    """ Class the represents a live pcap capture/injection device. """
    _OpenDevices = {}  # objectid -> low-level pcap dev
    _lock = Lock()
    __slots__ = ['_ffi', '_libpcap', '_base', '_pcapdev', '_devname', '_fd', '_user_callback', '_nroots']

    def __init__(self, device, snaplen, promisc, to_ms, nonblock):
        self._base = _PcapFfi.instance()
        self._ffi = self._base.ffi
        self._libpcap = self._base.lib
        self._fd = None
        self._user_callback = None

        errbuf = self._ffi.new("char []", 128)
        internal_name = None
        for dev in self._base._interfaces:
            if dev.name == device:
                internal_name = dev.internal_name
                break
        if internal_name is None:
            raise Exception("No such device {} exists.".format(device))
        self._devname = device
        self._pcapdev = None

        pcap = self._libpcap.pcap_open_live(bytes(internal_name, 'utf-8'), snaplen, promisc, to_ms, errbuf)
        if pcap == self._ffi.NULL:
            raise PcapException("Failed to open live device {}: {}".format(internal_name, self._ffi.string(errbuf)))

        if nonblock:
            rv = self._libpcap.pcap_setnonblock(pcap, 1, errbuf)
            if rv != 0:
                raise PcapException(
                    "Error setting pcap device in nonblocking state: {}".format(self._ffi.string(errbuf)))

        nblock = self._libpcap.pcap_getnonblock(pcap, errbuf)  # gather what happened
        snaplen = self._libpcap.pcap_snapshot(pcap)
        dl = self._libpcap.pcap_datalink(pcap)
        try:
            dl = Dlt(dl)
        except ValueError as e:
            raise PcapException("Don't know how to handle datalink type {}".format(dl))

        self._pcapdev = PcapDev(dl, nblock, snaplen, _PcapFfi.instance().version, pcap)
        self._fd = self._libpcap.pcap_get_selectable_fd(self._pcapdev.pcap)

        with PcapLiveDevice._lock:
            PcapLiveDevice._OpenDevices[id(self)] = self._pcapdev.pcap

    def recv_packet(self,  timeout=0.01, nroots=1, account_ip_padding_size=False):
        if timeout is None or timeout < 0:
            timeout = None
        if self._fd >= 0:
            try:
                xread, xwrite, xerr = select([self._fd], [], [self._fd], timeout)
            except PcapException:
                return None
            if xread:
                return self._base._recv_packet(self._pcapdev.pcap, nroots, account_ip_padding_size)
            else:
                return None  # timeout: return nothing
        else:
            # no select, no non-blocking mode.
            return self._base._recv_packet(self._pcapdev.pcap, nroots, account_ip_padding_size)

    def close(self):
        with PcapLiveDevice._lock:
            xid = id(self)
            del PcapLiveDevice._OpenDevices[xid]
        self._libpcap.pcap_close(self._pcapdev.pcap)


_PcapFfi()  # instantiate singleton


def check_source_type(source):
    if source is None:  # start on first up device
        for dev in pcap_devices():
            if dev.isup:
                print("Source not defined. Using {} as default value.".format(dev.name))
                return dev.name, 1
        raise OSError
    if os.path.isfile(str(source)):
        return str(source), 0
    else:  # check if valid device.
        for dev in pcap_devices():
            if str(source) == dev.name:
                return str(source), 1
    raise OSError("Streamer initialized on unfound source: {}".format(str(source)))


class NFObserver:
    def __init__(self, source=None, snaplen=65535, promisc=1, to_ms=0, non_block=True, nroots=1,
                 account_ip_padding_size=False):
        source_type = check_source_type(source)
        source = source_type[0]
        if source_type[1] == 1:  # live interface
            try:
                self.packet_generator = PcapLiveDevice(device=source, snaplen=snaplen, promisc=promisc, to_ms=to_ms,
                                                       nonblock=non_block)
            except PcapException:
                raise OSError("Root privilege needed for live capture on {} interface.".format(source))
        elif source_type[1] == 0:  # pcap case
            try:
                self.packet_generator = PcapReader(filename=source)
            except PcapException:
                raise OSError('Unable to read pcap format of: {}'.format(source))
        else:
            self.packet_generator = None
        self.nroots = nroots
        self.mode = source_type[1]
        self.safety_time = 0
        self.account_ip_padding_size = account_ip_padding_size

    def __iter__(self):
        if self.packet_generator is not None:
            try:
                while True:
                    try:
                        r = self.packet_generator.recv_packet(nroots=self.nroots,
                                                              account_ip_padding_size=self.account_ip_padding_size)
                        if r is None:
                            yield r  # trigger periodic cleaning
                        elif r == -2:
                            raise KeyboardInterrupt
                        elif r == 0:
                            pass
                        else:
                            if r.time >= self.safety_time:
                                self.safety_time = r.time
                            else:
                                r.time = self.safety_time
                            yield r
                    except PcapException:
                        pass
            except KeyboardInterrupt:
                return
