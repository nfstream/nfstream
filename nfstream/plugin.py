#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: plugin.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""
import ipaddress
from .ndpi import NDPI
ndpi = NDPI()


class NFPlugin(object):
    """ Metric class """
    def __init__(self, name=None, volatile=False, init_function=None):
        if name is None:
            self.name = type(self).__name__
        else:
            self.name = name
        if init_function is None:
            self.init_function = lambda pkt: 0  # called for first packet
        else:
            self.init_function = init_function
        self.volatile = volatile

    def process(self, pkt, flow):
        pass

    def giveup(self, flow):
        pass


def valid_plugins(plugins):
    """ Check NFPlugin name is unique """
    plugin_names = []
    for plugin in plugins:
        if isinstance(plugin, NFPlugin):
            plugin_names.append(plugin.name)
        else:
            raise TypeError
    if len(plugin_names) != len(list(set(plugin_names))):
        raise ValueError


class packet_direction_setter(NFPlugin):
    """ Setter for packet direction (volatile)"""
    def process(self, pkt, flow):
        if (flow.ip_src == pkt.ip_src) and (flow.src_port == pkt.src_port):
            pkt.close(0)
        else:
            pkt.close(1)


class first_seen(NFPlugin):
    """ Timestamp in milliseconds on first flow packet """


class last_seen(NFPlugin):
    """ Timestamp in milliseconds on last flow packet """
    def process(self, pkt, flow):
        flow.last_seen = pkt.time


class nfhash(NFPlugin):
    """ Flow nfstream hashed value """


class ip_src(NFPlugin):
    """ Integer value of IP source (volatile) """


class ip_dst(NFPlugin):
    """ Integer value of IP source (volatile) """


class version(NFPlugin):
    """ IP version """


class src_port(NFPlugin):
    """ Transport layer source port """


class dst_port(NFPlugin):
    """ Transport layer destination port """


class protocol(NFPlugin):
    """ Transport protocol identifier"""


class vlan_id(NFPlugin):
    """ VLAN identifier """


def ip_src_to_str(pkt):
    if pkt.version == 4:
        return str(ipaddress.IPv4Address(pkt.ip_src))
    else:
        return str(ipaddress.IPv6Address(pkt.ip_src)).replace(':0:', '::')


def ip_dst_to_str(pkt):
    if pkt.version == 4:
        return str(ipaddress.IPv4Address(pkt.ip_dst))
    else:
        return str(ipaddress.IPv6Address(pkt.ip_dst)).replace(':0:', '::')


class src_ip(NFPlugin):
    """ String representation of ip source """


class dst_ip(NFPlugin):
    """ String representation of ip destination """


class total_packets(NFPlugin):
    """ Flow bidirectional packets accumulator """
    def process(self, pkt, flow):
        flow.total_packets += 1


class total_bytes(NFPlugin):
    """ Flow bidirectional bytes accumulator """
    def process(self, pkt, flow):
        flow.total_bytes += pkt.length


class duration(NFPlugin):
    """ Flow total duration in milliseconds """
    def process(self, pkt, flow):
        flow.duration = pkt.time - flow.first_seen


class src2dst_packets(NFPlugin):
    """ Flow src -> dst packets accumulator """
    def process(self, pkt, flow):
        if pkt.direction == 0:
            flow.src2dst_packets += 1


class src2dst_bytes(NFPlugin):
    """ Flow src -> dst bytes accumulator """
    def process(self, pkt, flow):
        if pkt.direction == 0:
            flow.src2dst_bytes += pkt.length


class dst2src_packets(NFPlugin):
    """ Flow dst -> src packets accumulator """
    def process(self, pkt, flow):
        if pkt.direction == 1:
            flow.dst2src_packets += 1


class dst2src_bytes(NFPlugin):
    """ Flow dst -> src bytes accumulator """
    def process(self, pkt, flow):
        if pkt.direction == 1:
            flow.dst2src_bytes += pkt.length


class expiration_id(NFPlugin):
    """ Flow expiration ID: negative if custom, 0 if idle expiration, 1 if active expiration, 2 if natural """


def init_ndpi_structs(pkt):
    """ ndpi main structures initiators"""
    f = ndpi.new_ndpi_flow()
    s = ndpi.new_ndpi_id()
    d = ndpi.new_ndpi_id()
    p = ndpi.ndpi_detection_process_packet(f, pkt.raw, len(pkt.raw), pkt.time, s, d)
    return [f, s, d, p, 0]


def is_ndpi_proto(flow, id):
    if (flow.master_protocol == id) or (flow.app_protocol == id):
        return True
    else:
        return False


def collect_ndpi_information(flow, ndpi_flow, ndpi_protocol):
    """ collect ndpi flow informations """
    flow.app_protocol = ndpi_protocol.app_protocol
    flow.master_protocol = ndpi_protocol.master_protocol
    flow.application_name = ndpi.ndpi_protocol2name(ndpi_protocol)
    flow.category_name = ndpi.ndpi_category_get_name(ndpi_protocol.category)
    flow.server_info = ndpi.get_str_field(ndpi_flow.host_server_name)  # DNS and HTTP
    if is_ndpi_proto(flow, 7):  # HTTP
        flow.client_info = ndpi.get_str_field(ndpi_flow.protos.http.detected_os)
    elif is_ndpi_proto(flow, 92):  # SSH
        flow.client_info = ndpi.get_str_field(ndpi_flow.protos.ssh.client_signature)
        flow.server_info = ndpi.get_str_field(ndpi_flow.protos.ssh.server_signature)
    elif is_ndpi_proto(flow, 91) or ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_client) != '':  # TLS
        flow.client_info = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.client_certificate)
        flow.server_info = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.server_certificate)
        flow.j3a_client = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_client)
        flow.j3a_server = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_server)
    else:
        pass


class ndpi_structs(NFPlugin):
    def process(self, pkt, flow):
        tcp_not_enough = (flow.protocol == 6) and (flow.total_packets <= flow.max_tcp_dissections)
        udp_not_enough = (flow.protocol == 17) and (flow.total_packets <= flow.max_udp_dissections)
        if (tcp_not_enough or udp_not_enough) and flow.ndpi_structs[4] == 0:
            flow.ndpi_structs[3] = ndpi.ndpi_detection_process_packet(flow.ndpi_structs[0],
                                                                          pkt.raw,
                                                                          len(pkt.raw),
                                                                          pkt.time,
                                                                          flow.ndpi_structs[1],
                                                                          flow.ndpi_structs[2])
            collect_ndpi_information(flow, flow.ndpi_structs[0], flow.ndpi_structs[3])
        elif flow.ndpi_structs[4] == 0:  # we reached max and still not detected
            if flow.ndpi_structs[3].app_protocol == 0:
                flow.ndpi_structs[3] = ndpi.ndpi_detection_giveup(flow.ndpi_structs[0])
                flow.ndpi_structs[4] = 1
                collect_ndpi_information(flow, flow.ndpi_structs[0], flow.ndpi_structs[3])
        else:
            pass

    def giveup(self, flow):
        # flow expires and we failed to detect it.
        if flow.ndpi_structs[3].app_protocol == 0 and flow.ndpi_structs[4] == 0:
            flow.ndpi_structs[3] = ndpi.ndpi_detection_giveup(flow.ndpi_structs[0])
        collect_ndpi_information(flow, flow.ndpi_structs[0], flow.ndpi_structs[3])
        # Freeing allocated memory
        if flow.ndpi_structs[0] != ndpi.NULL:
            ndpi.ndpi_flow_free(flow.ndpi_structs[0])
            flow.ndpi_structs[0] = ndpi.NULL
        if flow.ndpi_structs[1] != ndpi.NULL:
            ndpi.ndpi_free(flow.ndpi_structs[1])
            flow.ndpi_structs[1] = ndpi.NULL
        if flow.ndpi_structs[2] != ndpi.NULL:
            ndpi.ndpi_free(flow.ndpi_structs[2])
            flow.ndpi_structs[2] = ndpi.NULL


class app_protocol(NFPlugin):
    """ ndpi proto.app_protocol id """


class master_protocol(NFPlugin):
    """ ndpi proto.master_protocol id """


class application_name(NFPlugin):
    """ ndpi application name """


class category_name(NFPlugin):
    """ ndpi category name """


class client_info(NFPlugin):
    """ client dissected information """


class server_info(NFPlugin):
    """ server dissected information """


class j3a_client(NFPlugin):
    """ client j3a fingerprint """


class j3a_server(NFPlugin):
    """ server j3a information """


nfstream_core_plugins = [packet_direction_setter(init_function=lambda p: None, volatile=True),
                         first_seen(init_function=lambda p: p.time),
                         last_seen(init_function=lambda p: p.time),
                         nfhash(init_function=lambda p: p.nfhash),
                         ip_src(init_function=lambda p: p.ip_src, volatile=True),
                         ip_dst(init_function=lambda p: p.ip_dst, volatile=True),
                         version(init_function=lambda p: p.version),
                         src_port(init_function=lambda p: p.src_port),
                         dst_port(init_function=lambda p: p.dst_port),
                         protocol(init_function=lambda p: p.protocol),
                         vlan_id(init_function=lambda p: p.vlan_id),
                         src_ip(init_function=ip_src_to_str),
                         dst_ip(init_function=ip_dst_to_str),
                         total_packets(init_function=lambda p: 1),
                         total_bytes(init_function=lambda p: p.length),
                         duration(),
                         src2dst_packets(init_function=lambda p: 1),
                         src2dst_bytes(init_function=lambda p: p.length),
                         dst2src_packets(),
                         dst2src_bytes(),
                         expiration_id()]

ndpi_plugins = [master_protocol(),
                app_protocol(),
                application_name(init_function=lambda p: ''),
                category_name(init_function=lambda p: ''),
                client_info(init_function=lambda p: ''),
                server_info(init_function=lambda p: ''),
                j3a_client(init_function=lambda p: ''),
                j3a_server(init_function=lambda p: ''),
                ndpi_structs(init_function=init_ndpi_structs, volatile=True)]

"""
class pktlen_max(NFPlugin):
    def process(self, pkt, flow):
        if pkt.length > flow.pktlen_max:
            flow.pktlen_max = pkt.length


class pktlen_min(NFPlugin):
    def process(self, pkt, flow):
        if pkt.length < flow.pktlen_min:
            flow.pktlen_min = pkt.length


class pktlen_mean(NFPlugin):
    def process(self, pkt, flow):
        delta = pkt.length - flow.pktlen_mean
        flow.pktlen_mean += delta / flow.total_packets
        flow.pktlen_std += delta * (pkt.length - flow.pktlen_mean)


class pktlen_std(NFPlugin):
    def giveup(self, flow):
        if flow.total_packets < 2:
            flow.pktlen_std = None
        else:
            flow.pktlen_std / (flow.total_packets - 1)
"""

"""
statistical_plugins = [pktlen_min(init_function=lambda p: p.length),
                       pktlen_max(init_function=lambda p: p.length),
                       pktlen_std(),
                       pktlen_mean(init_function=lambda p: p.length),]
"""