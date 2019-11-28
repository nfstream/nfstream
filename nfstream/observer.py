#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: observer.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""
from collections import namedtuple
from socket import ntohs, ntohl
from enum import Enum, IntEnum
from threading import Lock
from select import select
from cffi import FFI
import os.path
import sys

cc = """
typedef uint8_t u_char;
struct pcap;
typedef struct pcap pcap_t;
struct pcap_dumper;
typedef struct pcap_dumper pcap_dumper_t;
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
int pcap_findalldevs(pcap_if_t **, char *);
void pcap_freealldevs(pcap_if_t *);
struct pcap_pkthdr {
    long tv_sec;
    long tv_usec;
    unsigned int caplen;
    unsigned int len;
};

struct pcap_stat {
    unsigned int recv;
    unsigned int drop;
    unsigned int ifdrop;
};

typedef void (*pcap_handler)(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

pcap_t *pcap_open_dead(int, int);
pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
void pcap_dump_close(pcap_dumper_t *);
void pcap_dump(pcap_dumper_t *, struct pcap_pkthdr *, unsigned char *);

// live capture
pcap_t *pcap_create(const char *, char *); 
pcap_t *pcap_open_live(const char *, int, int, int, char *);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
int pcap_set_snaplen(pcap_t *, int);
int pcap_snapshot(pcap_t *);
int pcap_set_promisc(pcap_t *, int);

int pcap_set_timeout(pcap_t *, int);
int pcap_set_buffer_size(pcap_t *, int);

int pcap_set_tstamp_precision(pcap_t *, int);
int pcap_get_tstamp_precision(pcap_t *);
int pcap_set_tstamp_type(pcap_t *, int);
int pcap_list_tstamp_types(pcap_t *, int **);
void pcap_free_tstamp_types(int *);

int pcap_setdirection(pcap_t *, int); 
int pcap_datalink(pcap_t *);
int pcap_setnonblock(pcap_t *, int, char *); 
int pcap_getnonblock(pcap_t *, char *); 
int pcap_set_immediate_mode(pcap_t *, int);
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
int pcap_dispatch(pcap_t *, int, pcap_handler, unsigned char *);
int pcap_loop(pcap_t *, int, pcap_handler, unsigned char *);
void pcap_breakloop(pcap_t *);
int pcap_activate(pcap_t *);
void pcap_close(pcap_t *);
int pcap_get_selectable_fd(pcap_t *);
int pcap_sendpacket(pcap_t *, const unsigned char *, int);
char *pcap_geterr(pcap_t *);
char *pcap_lib_version();
int pcap_stats(pcap_t *, struct pcap_stat *);

struct bpf_insn;
struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn *bf_insns;
};
int pcap_setfilter(pcap_t *, struct bpf_program *);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, unsigned int);
void pcap_freecode(struct bpf_program *);
"""

cc_packed = """
struct nfstream_ethhdr
{
  u_char h_dest[6];
  u_char h_source[6];
  uint16_t h_proto;
};

struct nfstream_snap_extension
{
  uint16_t oui;
  uint8_t oui2;
  uint16_t proto_ID;
};
struct nfstream_llc_header_snap
{
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl;
  struct nfstream_snap_extension snap;
};
struct nfstream_chdlc
{
  uint8_t addr;
  uint8_t ctrl;
  uint16_t proto_code;
};
struct nfstream_radiotap_header
{
  uint8_t version;
  uint8_t pad;
  uint16_t len;
  uint32_t present;
  uint64_t MAC_timestamp;
  uint8_t flags;
};
struct nfstream_wifi_header
{
  uint16_t fc;
  uint16_t duration;
  u_char rcvr[6];
  u_char trsm[6];
  u_char dest[6];
  uint16_t seq_ctrl;
};
struct nfstream_mpls_header
{
  uint32_t ttl:8, s:1, exp:3, label:20;
};
extern union mpls {
  uint32_t u32;
  struct nfstream_mpls_header mpls;
} mpls;
struct nfstream_iphdr {
  uint8_t ihl:4, version:4;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};
struct nfstream_in6_addr {
  union {
    uint8_t u6_addr8[16];
    uint16_t u6_addr16[8];
    uint32_t u6_addr32[4];
  } u6_addr;
};
struct nfstream_ip6_hdrctl {
  uint32_t ip6_un1_flow;
  uint16_t ip6_un1_plen;
  uint8_t ip6_un1_nxt;
  uint8_t ip6_un1_hlim;
};
struct nfstream_ipv6hdr {
  struct nfstream_ip6_hdrctl ip6_hdr;
  struct nfstream_in6_addr ip6_src;
  struct nfstream_in6_addr ip6_dst;
};
struct nfstream_udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};
struct pp_32 {
    uint32_t value;
};
struct nfstream_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};
"""


TICK_RESOLUTION = 1000


PcapInterface = namedtuple('PcapInterface', ['name', 'internal_name', 'description', 'isloop', 'isup', 'isrunning'])
PcapPacket = namedtuple('PcapPacket', ['timestamp', 'capture_length', 'length', 'raw'])
PcapDev = namedtuple('PcapDev', ['dlt', 'nonblock', 'snaplen', 'version', 'pcap'])
tcpflags = namedtuple('tcpflags', ['syn', 'cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'fin'])


class NFPacket(object):
    def __init__(self, time, capture_length, length,
                 nfhash, ip_src, ip_dst, src_port, dst_port, protocol, vlan_id,
                 version, tcpflags, raw, root_idx):
        object.__setattr__(self, "time", time)
        object.__setattr__(self, "capture_length", capture_length)
        object.__setattr__(self, "length", length)
        object.__setattr__(self, "nfhash", nfhash)
        object.__setattr__(self, "ip_src", ip_src)
        object.__setattr__(self, "ip_dst", ip_dst)
        object.__setattr__(self, "src_port", src_port)
        object.__setattr__(self, "dst_port", dst_port)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "vlan_id", vlan_id)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "tcpflags", tcpflags)
        object.__setattr__(self, "raw", raw)
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


class _PcapFfi(object):
    """
    This class represents the low-level interface to the libpcap library.
    It encapsulates all the cffi calls and C/Python conversions, as well
    as translation of errors and error codes to PcapExceptions.  It is
    intended to be used as a singleton class through the PcapDumper
    and PcapLiveDevice classes, below.
    """
    _instance = None
    __slots__ = ['_ffi', '_libpcap', '_interfaces', '_windows']

    def __init__(self):
        """
        Assumption: this class is instantiated once in the main thread before
        any other threads have a chance to try instantiating it.
        """
        if _PcapFfi._instance:
            raise Exception("Can't initialize this class more than once!")

        _PcapFfi._instance = self
        self._windows = False
        self._ffi = FFI()
        self._ffi.cdef(cc, override=True)
        self._ffi.cdef(cc_packed, override=True, packed=1)
        if sys.platform == 'darwin':
            libname = 'libpcap.dylib'
        elif sys.platform == 'win32':
            libname = 'wpcap.dll'  # winpcap
            self._windows = True
        else:
            # if not macOS (darwin) or windows, assume we're on
            # some unix-based system and try for libpcap.so
            libname = 'libpcap.so'
        try:
            self._libpcap = self._ffi.dlopen(libname)
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
        """
        Find all the pcap-eligible devices on the local system.
        """
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

    def _process_packet(self, xdev, header, packet, nroots):
        # MPLS header
        mpls = self._ffi.new("union mpls *")
        # IP header
        iph = self._ffi.new("struct nfstream_iphdr *")
        # IPv6 header
        iph6 = self._ffi.new("struct nfstream_ipv6hdr *")
        # lengths and offsets
        eth_offset = 0
        radio_len = 0
        fc = 0
        type = 0
        wifi_len = 0
        pyld_eth_len = 0
        check = 0
        ip_offset = 0
        ip_len = 0
        frag_off = 0
        vlan_id = 0
        proto = 0
        time = 0
        time = (header.tv_sec * TICK_RESOLUTION) + (header.tv_usec / (1000000 / TICK_RESOLUTION))

        datalink_type = self._libpcap.pcap_datalink(xdev)
        datalink_check = True
        while datalink_check:
            datalink_check = False
            if Dlt(datalink_type) == Dlt.DLT_NULL:
                tmp_dlt_null = self._ffi.cast('struct pp_32 *', packet + eth_offset)
                if int(ntohs(tmp_dlt_null.value)) == 2:
                    type = 0x0800
                else:
                    type = 0x86dd
                ip_offset = 4 + eth_offset
            elif Dlt(datalink_type) == Dlt.DLT_PPP_SERIAL:  # Cisco PPP in HDLC - like framing - 50
                chdlc = self._ffi.cast('struct nfstream_chdlc *', packet + eth_offset)
                ip_offset = self._ffi.sizeof('struct nfstream_chdlc')  # CHDLC_OFF = 4
                type = ntohs(chdlc.proto_code)
            elif (Dlt(datalink_type) == Dlt.DLT_C_HDLC) or (Dlt(datalink_type) == Dlt.DLT_PPP):  # Cisco PPP - 9 or 104
                chdlc = self._ffi.cast('struct nfstream_chdlc *', packet + eth_offset)  # CHDLC_OFF = 4
                ip_offset = self._ffi.sizeof('struct nfstream_chdlc')  # CHDLC_OFF = 4
                type = ntohs(chdlc.proto_code)
            elif Dlt(datalink_type) == Dlt.DLT_EN10MB:  # IEEE 802.3 Ethernet - 1 */
                ethernet = self._ffi.cast('struct nfstream_ethhdr *', packet + eth_offset)
                ip_offset = self._ffi.sizeof('struct nfstream_ethhdr') + eth_offset
                check = ntohs(ethernet.h_proto)
                if check <= 1500:
                    pyld_eth_len = check
                elif check >= 1536:
                    type = check

                if pyld_eth_len != 0:
                    llc = self._ffi.cast('struct nfstream_llc_header_snap *', packet + ip_offset)
                    if (llc.dsap == 0xaa) or (llc.ssap == 0xaa):  # check for LLC layer with SNAP ext
                        type = llc.snap.proto_ID
                        ip_offset += 8
                    elif (llc.dsap == 0x42) or (llc.ssap == 0x42):  # No SNAP ext
                        return None
            elif Dlt(datalink_type) == Dlt.DLT_LINUX_SLL:  # Linux Cooked Capture - 113
                type = (packet[eth_offset+14] << 8) + packet[eth_offset+15]
                ip_offset = 16 + eth_offset
            elif Dlt(datalink_type) == Dlt.DLT_IEEE802_11_RADIO:  # Radiotap link - layer - 127
                radiotap = self._ffi.cast('struct nfstream_radiotap_header *', packet + eth_offset)
                radio_len = radiotap.len
                if (radiotap.flags & 0x50) == 0x50:  # Check Bad FCS presence
                    return None
                # Calculate 802.11 header length(variable)
                wifi = self._ffi.cast('struct nfstream_wifi_header *', packet + (eth_offset + radio_len))
                fc = wifi.fc
                # Check wifi data presence
                if fcf_type(fc) == 0x2:
                    if (fcf_to_ds(fc) and fcf_from_ds(fc) == 0x0) or (fcf_to_ds(fc) == 0x0 and fcf_from_ds(fc)):
                        wifi_len = 26  # + 4 byte fcs
                else:
                    pass
                # Check ether_type from LLC
                llc = self._ffi.cast('struct nfstream_llc_header_snap *', packet + (eth_offset + wifi_len + radio_len))
                if llc.dsap == 0xaa:
                    type = ntohs(llc.snap.proto_ID)
                # Set IP header offset
                ip_offset = wifi_len + radio_len + self._ffi.sizeof('struct nfstream_llc_header_snap') + eth_offset
            elif Dlt(datalink_type) == Dlt.DLT_RAW:
                ip_offset = 0
                eth_offset = 0
            else:
                return None

            if type == 0x8100:
                vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF
                type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3]
                ip_offset += 4
                if type == 0x8100:  # Double tagging for 802.1Q
                    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF
                    type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3]
                    ip_offset += 4
            elif (type == 0x8847) or (type == 0x8848):
                tmp_u32 = self._ffi.cast('struct pp_32 *', packet + ip_offset)
                mpls.u32 = int(ntohl(tmp_u32.value))
                type = 0x0800
                ip_offset += 4
                while not mpls.mpls.s:
                    tmp_u32_loop = self._ffi.cast('struct pp_32 *', packet + ip_offset)
                    mpls.u32 = int(ntohl(tmp_u32_loop.value))
                    ip_offset += 4
            elif type == 0x8864:
                type = 0x0800
                ip_offset += 8
            else:
                pass

            ip_check = True
            while ip_check:
                ip_check = False
                # Check and set IP header size and total packet length
                iph = self._ffi.cast('struct nfstream_iphdr *', packet + ip_offset)
                # Just work on Ethernet packets that contain IP
                if (type == 0x0800) and (header.caplen >= ip_offset):
                    frag_off = ntohs(iph.frag_off)
                    if header.caplen < header.len:
                        pass
                if iph.version == 4:
                    ip_len = iph.ihl * 4
                    iph6 = self._ffi.NULL
                    if iph.protocol == 41:  # IPPROTO_IPV6
                        ip_offset += ip_len
                        ip_check = True
                    if (frag_off & 0x1FFF) != 0:
                        return None
                elif iph.version == 6:
                    iph6 = self._ffi.cast('struct nfstream_ipv6hdr *', packet + ip_offset)
                    ip_len = self._ffi.sizeof('struct nfstream_ipv6hdr')
                    if iph6.ip6_hdr.ip6_un1_nxt == 60:  # IPv6 destination option
                        options = self._ffi.cast('uint8_t *', packet + (ip_offset + ip_len))
                        ip_len += 8 * (options[1] + 1)
                    iph = self._ffi.NULL
                else:
                    return None

        l4_offset = 0
        ipsize = 0
        src_addr = 0
        dst_addr = 0
        l4_packet_len = 0
        version = 0

        nfstream_hash = 0
        if iph6 == self._ffi.NULL:
            version = 4
            l4_packet_len = ntohs(iph.tot_len) - (iph.ihl * 4)
            ipsize = header.caplen - ip_offset
            proto = iph.protocol
            src_addr = ntohl(iph.saddr)
            dst_addr = ntohl(iph.daddr)
            nfstream_hash += iph.saddr + iph.daddr + proto + vlan_id
        else:
            version = 6
            src_addr = ntohl(
                iph6.ip6_src.u6_addr.u6_addr32[0]
            ) << 96 | ntohl(
                iph6.ip6_src.u6_addr.u6_addr32[1]
            ) << 64 | ntohl(
                iph6.ip6_src.u6_addr.u6_addr32[2]
            ) << 32 | ntohl(
                iph6.ip6_src.u6_addr.u6_addr32[3]
            )
            dst_addr = ntohl(
                iph6.ip6_dst.u6_addr.u6_addr32[0]
            ) << 96 | ntohl(
                iph6.ip6_dst.u6_addr.u6_addr32[1]
            ) << 64 | ntohl(
                iph6.ip6_dst.u6_addr.u6_addr32[2]
            ) << 32 | ntohl(
                iph6.ip6_dst.u6_addr.u6_addr32[3]
            )
            proto = iph6.ip6_hdr.ip6_un1_nxt
            if proto == 60:
                options = self._ffi.cast('uint8_t *', iph6) + self._ffi.sizeof('struct nfstream_ipv6hdr')
                proto = options[0]
            l4_packet_len = ntohs(iph6.ip6_hdr.ip6_un1_plen)
            nfstream_hash += (
                                     iph6.ip6_src.u6_addr.u6_addr32[2] + iph6.ip6_src.u6_addr.u6_addr32[3]
                             ) + (
                    iph6.ip6_dst.u6_addr.u6_addr32[2] + iph6.ip6_dst.u6_addr.u6_addr32[3]
            ) + proto + vlan_id

        if version == 4:
            if ipsize < 20:
                return None
            if ((iph.ihl * 4) > ipsize) or (ipsize < ntohs(iph.tot_len)):
                return None
            l4_offset = iph.ihl * 4
            l3 = self._ffi.cast('uint8_t *', iph)
        else:
            l4_offset = self._ffi.sizeof('struct nfstream_ipv6hdr')
            l3 = self._ffi.cast('uint8_t *', iph6)

        l4 = self._ffi.cast('uint8_t *', l3) + l4_offset
        syn, cwr, ece, urg, ack, psh, rst, fin = 0, 0, 0, 0, 0, 0, 0, 0
        if (proto == 6) and l4_packet_len >= self._ffi.sizeof('struct nfstream_tcphdr'):
            tcph = self._ffi.cast('struct nfstream_tcphdr *', l4)
            sport = int(ntohs(tcph.source))
            dport = int(ntohs(tcph.dest))
            syn = int(tcph.syn)
            cwr = int(tcph.cwr)
            ece = int(tcph.ece)
            urg = int(tcph.urg)
            ack = int(tcph.ack)
            psh = int(tcph.psh)
            rst = int(tcph.rst)
            fin = int(tcph.fin)
        elif (proto == 17) and l4_packet_len >= self._ffi.sizeof('struct nfstream_udphdr'):
            udph = self._ffi.cast('struct nfstream_udphdr *', l4)
            sport = int(ntohs(udph.source))
            dport = int(ntohs(udph.dest))
        else:
            sport = 0
            dport = 0
        nfstream_hash += sport + dport
        if version == 4:
            return NFPacket(time=int(time),
                            capture_length=header.caplen,
                            length=header.len,
                            nfhash=nfstream_hash,
                            ip_src=src_addr,
                            ip_dst=dst_addr,
                            src_port=sport,
                            dst_port=dport,
                            protocol=proto,
                            vlan_id=vlan_id,
                            version=version,
                            tcpflags=tcpflags(syn=syn, cwr=cwr, ece=ece, urg=urg, ack=ack, psh=psh, rst=rst, fin=fin),
                            raw=bytes(xffi.buffer(iph, ipsize)),
                            root_idx=nfstream_hash % nroots)
        else:
            return NFPacket(time=int(time),
                            capture_length=header.caplen,
                            length=header.len,
                            nfhash=nfstream_hash,
                            ip_src=src_addr,
                            ip_dst=dst_addr,
                            src_port=sport,
                            dst_port=dport,
                            protocol=proto,
                            vlan_id=vlan_id,
                            version=version,
                            tcpflags=tcpflags(syn=syn, cwr=cwr, ece=ece, urg=urg, ack=ack, psh=psh, rst=rst, fin=fin),
                            raw=bytes(xffi.buffer(iph6, header.len - ip_offset)),
                            root_idx=nfstream_hash % nroots)

    def _recv_packet(self, xdev, nroots=1):
        phdr = self._ffi.new("struct pcap_pkthdr **")
        pdata = self._ffi.new("unsigned char **")
        rv = self._libpcap.pcap_next_ex(xdev, phdr, pdata)
        if rv == 1:
            return self._process_packet(xdev, phdr[0], pdata[0], nroots)
        elif rv == 0:
            # timeout; nothing to return
            return 0
        elif rv == -1:
            # error on receive; raise an exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xdev))
            raise PcapException("Error receiving packet: {}".format(s))
        elif rv == -2:
            # reading from savefile, but none left
            return -2

    def _set_filter(self, xdev, filterstr):
        bpf = self._ffi.new("struct bpf_program *")
        cfilter = self._ffi.new("char []", bytes(filterstr, 'ascii'))
        compile_result = self._libpcap.pcap_compile(xdev, bpf, cfilter, 0, 0xffffffff)
        if compile_result < 0:
            # get error, raise exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xdev))
            raise PcapException("Error compiling filter expression: {}".format(s))

        sf_result = self._libpcap.pcap_setfilter(xdev, bpf)
        if sf_result < 0:
            # get error, raise exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xdev))
            raise PcapException("Error setting filter on pcap handle: {}".format(s))
        self._libpcap.pcap_freecode(bpf)


def pcap_devices():
    return _PcapFfi.instance().devices


class PcapReader(object):
    """
    Class the represents a reader of an existing pcap capture file.
    """
    __slots__ = ['_ffi', '_libpcap', '_base', '_pcapdev', '_user_callback']

    def __init__(self, filename, filterstr=None):
        self._base = _PcapFfi.instance()
        self._ffi = self._base.ffi
        self._libpcap = self._base.lib
        self._user_callback = None

        errbuf = self._ffi.new("char []", 128)
        pcap = self._libpcap.pcap_open_offline(bytes(filename, 'utf-8'), errbuf)
        if pcap == self._ffi.NULL:
            raise PcapException(
                "Failed to open pcap file for reading: {}: {}".format(filename, self._ffi.string(errbuf)))

        dl = self._libpcap.pcap_datalink(pcap)
        try:
            dl = Dlt(dl)
        except ValueError as e:
            raise PcapException("Don't know how to handle datalink type {}".format(dl))
        self._pcapdev = PcapDev(dl, 0, 0, _PcapFfi.instance().version, pcap)

        if filterstr is not None:
            self._base._set_filter(pcap, filterstr)

    def close(self):
        self._libpcap.pcap_close(self._pcapdev.pcap)

    def recv_packet(self, nroots=1):
        return self._base._recv_packet(self._pcapdev.pcap, nroots)

    def set_filter(self, filterstr):
        self._base._set_filter(self._pcapdev.pcap, filterstr)


class PcapLiveDevice(object):
    """
    Class the represents a live pcap capture/injection device.
    """
    _OpenDevices = {}  # objectid -> low-level pcap dev
    _lock = Lock()
    __slots__ = ['_ffi', '_libpcap', '_base', '_pcapdev', '_devname', '_fd', '_user_callback', '_nroots']

    def __init__(self, device, snaplen, filterstr, promisc, to_ms, nonblock):
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

        pcap = self._libpcap.pcap_open_live(bytes(internal_name, 'ascii'), snaplen, promisc, to_ms, errbuf)
        if pcap == self._ffi.NULL:
            raise PcapException("Failed to open live device {}: {}".format(internal_name, self._ffi.string(errbuf)))

        if nonblock:
            rv = self._libpcap.pcap_setnonblock(pcap, 1, errbuf)
            if rv != 0:
                raise PcapException(
                    "Error setting pcap device in nonblocking state: {}".format(self._ffi.string(errbuf)))

        # gather what happened
        nblock = self._libpcap.pcap_getnonblock(pcap, errbuf)
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

        if filterstr is not None:
            self.set_filter(filterstr)

    def recv_packet(self,  timeout=0.01, nroots=1):
        if timeout is None or timeout < 0:
            timeout = None
        if self._fd >= 0:
            try:
                xread, xwrite, xerr = select([self._fd], [], [self._fd], timeout)
            except PcapException:
                return None
            if xread:
                return self._base._recv_packet(self._pcapdev.pcap, nroots)
            # timeout; return nothing
            return None
        else:
            # no select, no non-blocking mode.  block away, my friend.
            return self._base._recv_packet(self._pcapdev.pcap, nroots)

    def close(self):
        with PcapLiveDevice._lock:
            xid = id(self)
            del PcapLiveDevice._OpenDevices[xid]
        self._libpcap.pcap_close(self._pcapdev.pcap)

    def set_filter(self, filterstr):
        self._base._set_filter(self._pcapdev.pcap, filterstr)


_PcapFfi()  # instantiate singleton
xffi = _PcapFfi.instance().ffi


def check_source_type(source):
    if source is None:  # start on first up device
        for dev in pcap_devices():
            if dev.isup:
                print("Streamer source not defined. Set to interface {} as default value.".format(dev.name))
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
    def __init__(self, source=None, snaplen=65535, promisc=1, to_ms=0, filter_str=None, non_block=True, nroots=1):
        source_type = check_source_type(source)
        source = source_type[0]
        if source_type[1] == 1:  # Live interface
            try:
                self.packet_generator = PcapLiveDevice(device=source, snaplen=snaplen, promisc=promisc, to_ms=to_ms,
                                                       filterstr=filter_str, nonblock=non_block)
            except PcapException:
                raise OSError("Root privilege needed for live capture on {} interface.".format(source))
        elif source_type[1] == 0:  # pcap case
            try:
                self.packet_generator = PcapReader(filename=source, filterstr=filter_str)
            except PcapException:
                raise OSError('Unable to read pcap format of: {}'.format(source))
        else:
            self.packet_generator = None
        self.nroots = nroots
        self.processed_pkts = 0
        self.mode = source_type[1]

    def __iter__(self):
        if self.packet_generator is not None:
            try:
                while True:
                    try:
                        r = self.packet_generator.recv_packet(nroots=self.nroots)
                        self.processed_pkts += 1  # increment total processed packet counter
                        if r is None:
                            yield r  # trigger cleaning
                        elif r == -2:
                            raise KeyboardInterrupt
                        elif r == 0:
                            pass
                        else:
                            yield r
                    except PcapException:
                        pass
            except KeyboardInterrupt:
                return