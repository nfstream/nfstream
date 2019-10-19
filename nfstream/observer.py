#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from collections import namedtuple
import dpkt
import pcap

""" Abstraction structure for any packet input type."""
PacketInfo = namedtuple('PacketInfo', ['ts', 'len', 'raw',
                                       'mac_src', 'mac_dst', 'ip_version',
                                       'ip_src', 'ip_dst', 'ip_protocol',
                                       'ip_src_b', 'ip_dst_b',
                                       'src_port', 'dst_port'])


def process_packet(ts, buf):
    """ process the contents of pcap packet """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except dpkt.dpkt.NeedData:
        return
    transport = dpkt.udp.UDP(sport=0, dport=0)  # Fake layer for non UPD/TCP packets
    if isinstance(eth.data, dpkt.ip.IP):
        ip_version = 4
    elif isinstance(eth.data, dpkt.ip6.IP6):
        ip_version = 6
    else:
        return
    ip = eth.data
    move_up = True
    while move_up:
        if isinstance(ip.data, dpkt.tcp.TCP):
            transport = ip.data
            move_up = False
        elif isinstance(ip.data, dpkt.udp.UDP):
            transport = ip.data
            move_up = False
        elif isinstance(ip.data, dpkt.ip6.IP6):
            ip = ip.data
        else:
            move_up = False
    return PacketInfo(ts=int(ts*1000), len=len(buf), raw=bytes(ip),
                      mac_src=eth.src, mac_dst=eth.dst, ip_version=ip_version,
                      ip_src=int.from_bytes(ip.src, "big"), ip_dst=int.from_bytes(ip.dst, "big"),
                      ip_src_b=ip.src, ip_dst_b=ip.dst,
                      src_port=transport.sport, dst_port=transport.dport, ip_protocol=ip.p)


class Observer:
    def __init__(self, source=None,
                 snaplen=65535,
                 promisc=False,
                 timeout_ms=0,
                 no_buffering=1,
                 rfmon=0,
                 timestamp_in_ns=0):
        self.source = source
        self.snaplen = snaplen
        self.promisc = promisc
        self.timeout_ms = timeout_ms
        self.no_buffering = no_buffering
        self.timestamp_in_ns = timestamp_in_ns
        self.rfmon = rfmon
        self.packet_generator = None
        self.packet_generator = pcap.pcap(name=self.source,
                                          snaplen=self.snaplen,
                                          promisc=self.promisc,
                                          timeout_ms=self.timeout_ms,
                                          immediate=self.no_buffering,
                                          timestamp_in_ns=self.timestamp_in_ns,
                                          rfmon=self.rfmon)

    def __iter__(self):
        if self.packet_generator is not None:
            for timestamp, packet in self.packet_generator:
                packet_information = process_packet(timestamp, packet)
                yield packet_information
