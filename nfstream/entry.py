#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
entry.py
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

from collections import namedtuple
from math import sqrt
import ipaddress


class ExpireOnInit(Exception):
    """Base class for other exceptions"""
    pass


nf_packet = namedtuple('NFPacket', ['time',
                                    'direction',
                                    'raw_size',
                                    'ip_size',
                                    'transport_size',
                                    'payload_size',
                                    'src_ip',
                                    'dst_ip',
                                    'src_port',
                                    'dst_port',
                                    'protocol',
                                    'vlan_id',
                                    'ip_version',
                                    'ip_packet',
                                    'syn',
                                    'cwr',
                                    'ece',
                                    'urg',
                                    'ack',
                                    'psh',
                                    'rst',
                                    'fin'])


class UDPS(object):
    pass


def pythonize_packet(packet, ffi):
    """ convert a cdata packet to a namedtuple """
    return nf_packet(time=packet.time,
                     direction=packet.direction,
                     raw_size=packet.raw_size,
                     ip_size=packet.ip_size,
                     transport_size=packet.transport_size,
                     payload_size=packet.payload_size,
                     src_ip=ffi.string(packet.src_name).decode('utf-8', errors='ignore'),
                     dst_ip=ffi.string(packet.dst_name).decode('utf-8', errors='ignore'),
                     src_port=packet.src_port,
                     dst_port=packet.dst_port,
                     protocol=packet.protocol,
                     vlan_id=packet.vlan_id,
                     ip_version=packet.ip_version,
                     ip_packet=bytes(ffi.buffer(packet.ip_content, packet.ip_content_len)),
                     syn=packet.syn,
                     cwr=packet.cwr,
                     ece=packet.ece,
                     urg=packet.urg,
                     ack=packet.ack,
                     psh=packet.psh,
                     rst=packet.rst,
                     fin=packet.fin)


class NFEntry(object):
    __slots__ = ('id',
                 'expiration_id',
                 'src_ip',
                 'src_ip_is_private',
                 'src_port',
                 'dst_ip',
                 'dst_ip_is_private',
                 'dst_port',
                 'protocol',
                 'ip_version',
                 'vlan_id',
                 'bidirectional_first_seen_ms',
                 'bidirectional_last_seen_ms',
                 'bidirectional_duration_ms',
                 'bidirectional_packets',
                 'bidirectional_bytes',
                 'src2dst_first_seen_ms',
                 'src2dst_last_seen_ms',
                 'src2dst_duration_ms',
                 'src2dst_packets',
                 'src2dst_bytes',
                 'dst2src_first_seen_ms',
                 'dst2src_last_seen_ms',
                 'dst2src_duration_ms',
                 'dst2src_packets',
                 'dst2src_bytes',
                 'bidirectional_min_ps',
                 'bidirectional_mean_ps',
                 'bidirectional_stddev_ps',
                 'bidirectional_max_ps',
                 'src2dst_min_ps',
                 'src2dst_mean_ps',
                 'src2dst_stddev_ps',
                 'src2dst_max_ps',
                 'dst2src_min_ps',
                 'dst2src_mean_ps',
                 'dst2src_stddev_ps',
                 'dst2src_max_ps',
                 'bidirectional_min_piat_ms',
                 'bidirectional_mean_piat_ms',
                 'bidirectional_stddev_piat_ms',
                 'bidirectional_max_piat_ms',
                 'src2dst_min_piat_ms',
                 'src2dst_mean_piat_ms',
                 'src2dst_stddev_piat_ms',
                 'src2dst_max_piat_ms',
                 'dst2src_min_piat_ms',
                 'dst2src_mean_piat_ms',
                 'dst2src_stddev_piat_ms',
                 'dst2src_max_piat_ms',
                 'bidirectional_syn_packets',
                 'bidirectional_cwr_packets',
                 'bidirectional_ece_packets',
                 'bidirectional_urg_packets',
                 'bidirectional_ack_packets',
                 'bidirectional_psh_packets',
                 'bidirectional_rst_packets',
                 'bidirectional_fin_packets',
                 'src2dst_syn_packets',
                 'src2dst_cwr_packets',
                 'src2dst_ece_packets',
                 'src2dst_urg_packets',
                 'src2dst_ack_packets',
                 'src2dst_psh_packets',
                 'src2dst_rst_packets',
                 'src2dst_fin_packets',
                 'dst2src_syn_packets',
                 'dst2src_cwr_packets',
                 'dst2src_ece_packets',
                 'dst2src_urg_packets',
                 'dst2src_ack_packets',
                 'dst2src_psh_packets',
                 'dst2src_rst_packets',
                 'dst2src_fin_packets',
                 'application_name',
                 'application_category_name',
                 'application_is_guessed',
                 'requested_server_name',
                 'client_fingerprint',
                 'server_fingerprint',
                 'http_user_agent',
                 'http_content_type',
                 '_C',
                 'udps')

    def __init__(self, packet, ffi, lib, udps, sync, accounting_mode, dissect, max_tcp_dissections,
                 max_udp_dissections, statistics, dissector):
        self.id = 0
        self.expiration_id = 0
        self._C = lib.meter_initialize_entry(packet, accounting_mode, statistics, dissect, max_tcp_dissections,
                                             max_udp_dissections, dissector)
        if self._C == ffi.NULL:
            raise OSError("Not enough memory for new flow creation.")
        self.src_ip = ffi.string(self._C.src_ip).decode('utf-8', errors='ignore')
        self.src_ip_is_private = int(ipaddress.ip_address(self.src_ip).is_private)
        self.src_port = self._C.src_port
        self.dst_ip = ffi.string(self._C.dst_ip).decode('utf-8', errors='ignore')
        self.dst_ip_is_private = int(ipaddress.ip_address(self.dst_ip).is_private)
        self.dst_port = self._C.dst_port
        self.protocol = self._C.protocol
        self.ip_version = self._C.ip_version
        self.vlan_id = self._C.vlan_id
        self.bidirectional_first_seen_ms = self._C.bidirectional_first_seen_ms
        self.bidirectional_last_seen_ms = self._C.bidirectional_last_seen_ms
        self.bidirectional_duration_ms = self._C.bidirectional_duration_ms
        self.bidirectional_packets = self._C.bidirectional_packets
        self.bidirectional_bytes = self._C.bidirectional_bytes
        self.src2dst_first_seen_ms = self._C.src2dst_first_seen_ms
        self.src2dst_last_seen_ms = self._C.src2dst_last_seen_ms
        self.src2dst_duration_ms = self._C.src2dst_duration_ms
        self.src2dst_packets = self._C.src2dst_packets
        self.src2dst_bytes = self._C.src2dst_bytes
        self.dst2src_first_seen_ms = self._C.dst2src_first_seen_ms
        self.dst2src_last_seen_ms = self._C.dst2src_last_seen_ms
        self.dst2src_duration_ms = self._C.dst2src_duration_ms
        self.dst2src_packets = self._C.dst2src_packets
        self.dst2src_bytes = self._C.dst2src_bytes
        if statistics:
            self.bidirectional_min_ps = self._C.bidirectional_min_ps
            self.bidirectional_mean_ps = self._C.bidirectional_mean_ps
            self.bidirectional_stddev_ps = self._C.bidirectional_stddev_ps
            self.bidirectional_max_ps = self._C.bidirectional_max_ps
            self.src2dst_min_ps = self._C.src2dst_min_ps
            self.src2dst_mean_ps = self._C.src2dst_mean_ps
            self.src2dst_stddev_ps = self._C.src2dst_stddev_ps
            self.src2dst_max_ps = self._C.src2dst_max_ps
            self.dst2src_min_ps = self._C.dst2src_min_ps
            self.dst2src_mean_ps = self._C.dst2src_mean_ps
            self.dst2src_stddev_ps = self._C.dst2src_stddev_ps
            self.dst2src_max_ps = self._C.dst2src_max_ps
            self.bidirectional_min_piat_ms = self._C.bidirectional_min_piat_ms
            self.bidirectional_mean_piat_ms = self._C.bidirectional_mean_piat_ms
            self.bidirectional_stddev_piat_ms = self._C.bidirectional_stddev_piat_ms
            self.bidirectional_max_piat_ms = self._C.bidirectional_max_piat_ms
            self.src2dst_min_piat_ms = self._C.src2dst_min_piat_ms
            self.src2dst_mean_piat_ms = self._C.src2dst_mean_piat_ms
            self.src2dst_stddev_piat_ms = self._C.src2dst_stddev_piat_ms
            self.src2dst_max_piat_ms = self._C.src2dst_max_piat_ms
            self.dst2src_min_piat_ms = self._C.dst2src_min_piat_ms
            self.dst2src_mean_piat_ms = self._C.dst2src_mean_piat_ms
            self.dst2src_stddev_piat_ms = self._C.dst2src_stddev_piat_ms
            self.dst2src_max_piat_ms = self._C.dst2src_max_piat_ms
            self.bidirectional_syn_packets = self._C.bidirectional_syn_packets
            self.bidirectional_cwr_packets = self._C.bidirectional_cwr_packets
            self.bidirectional_ece_packets = self._C.bidirectional_ece_packets
            self.bidirectional_urg_packets = self._C.bidirectional_urg_packets
            self.bidirectional_ack_packets = self._C.bidirectional_ack_packets
            self.bidirectional_psh_packets = self._C.bidirectional_psh_packets
            self.bidirectional_rst_packets = self._C.bidirectional_rst_packets
            self.bidirectional_fin_packets = self._C.bidirectional_fin_packets
            self.src2dst_syn_packets = self._C.src2dst_syn_packets
            self.src2dst_cwr_packets = self._C.src2dst_cwr_packets
            self.src2dst_ece_packets = self._C.src2dst_ece_packets
            self.src2dst_urg_packets = self._C.src2dst_urg_packets
            self.src2dst_ack_packets = self._C.src2dst_ack_packets
            self.src2dst_psh_packets = self._C.src2dst_psh_packets
            self.src2dst_rst_packets = self._C.src2dst_rst_packets
            self.src2dst_fin_packets = self._C.src2dst_fin_packets
            self.dst2src_syn_packets = self._C.dst2src_syn_packets
            self.dst2src_cwr_packets = self._C.dst2src_cwr_packets
            self.dst2src_ece_packets = self._C.dst2src_ece_packets
            self.dst2src_urg_packets = self._C.dst2src_urg_packets
            self.dst2src_ack_packets = self._C.dst2src_ack_packets
            self.dst2src_psh_packets = self._C.dst2src_psh_packets
            self.dst2src_rst_packets = self._C.dst2src_rst_packets
            self.dst2src_fin_packets = self._C.dst2src_fin_packets
        if dissect:
            self.application_name = ffi.string(self._C.application_name).decode('utf-8', errors='ignore')
            self.application_category_name = ffi.string(self._C.category_name).decode('utf-8', errors='ignore')
            self.application_is_guessed = self._C.guessed
            self.requested_server_name = ffi.string(self._C.requested_server_name).decode('utf-8', errors='ignore')
            self.client_fingerprint = ffi.string(self._C.c_hash).decode('utf-8', errors='ignore')
            self.server_fingerprint = ffi.string(self._C.s_hash).decode('utf-8', errors='ignore')
            self.http_user_agent = ffi.string(self._C.user_agent).decode('utf-8', errors='ignore')
            self.http_content_type = ffi.string(self._C.content_type).decode('utf-8', errors='ignore')
        if sync:
            self.udps = UDPS()
            for udp in udps:
                udp.on_init(pythonize_packet(packet, ffi), self)

    def update(self, packet, idle_timeout, active_timeout, ffi, lib, udps, sync, accounting_mode,
               dissect, max_tcp_dissections, max_udp_dissections, statistics, dissector):
        ret = lib.meter_update_entry(self._C, packet, idle_timeout, active_timeout, accounting_mode, statistics,
                                     dissect, max_tcp_dissections, max_udp_dissections, dissector)
        if ret > 0:
            self.expiration_id = ret - 1
            return self.expire(udps, sync, dissect, statistics, ffi, lib, dissector)
        else:
            if sync:
                self.sync(dissect, statistics, ffi)
                for udp in udps:
                    udp.on_update(pythonize_packet(packet, ffi), self)
                if self.expiration_id == -1:
                    return self.expire(udps, sync, dissect, statistics, ffi, lib, dissector)

    def expire(self, udps, sync, dissect, statistics, ffi, lib, dissector):
        lib.meter_expire_entry(self._C, dissect, dissector)
        self.sync(dissect, statistics, ffi)
        if sync:
            for udp in udps:
                udp.on_expire(self)
        lib.meter_free_entry(self._C, dissect)
        del self._C
        return self

    def sync(self, dissect, statistics, ffi):
        self.bidirectional_last_seen_ms = self._C.bidirectional_last_seen_ms
        self.bidirectional_duration_ms = self._C.bidirectional_duration_ms
        self.bidirectional_packets = self._C.bidirectional_packets
        self.bidirectional_bytes = self._C.bidirectional_bytes
        self.src2dst_last_seen_ms = self._C.src2dst_last_seen_ms
        self.src2dst_duration_ms = self._C.src2dst_duration_ms
        self.src2dst_packets = self._C.src2dst_packets
        self.src2dst_bytes = self._C.src2dst_bytes
        self.dst2src_first_seen_ms = self._C.dst2src_first_seen_ms
        self.dst2src_last_seen_ms = self._C.dst2src_last_seen_ms
        self.dst2src_duration_ms = self._C.dst2src_duration_ms
        self.dst2src_packets = self._C.dst2src_packets
        self.dst2src_bytes = self._C.dst2src_bytes
        if statistics:
            self.bidirectional_min_ps = self._C.bidirectional_min_ps
            self.bidirectional_mean_ps = self._C.bidirectional_mean_ps
            bidirectional_packets = self.bidirectional_packets
            if bidirectional_packets > 1:
                self.bidirectional_stddev_ps = sqrt(self._C.bidirectional_stddev_ps/(bidirectional_packets - 1))
            self.bidirectional_max_ps = self._C.bidirectional_max_ps
            self.src2dst_min_ps = self._C.src2dst_min_ps
            self.src2dst_mean_ps = self._C.src2dst_mean_ps
            src2dst_packets = self.src2dst_packets
            if src2dst_packets > 1:
                self.src2dst_stddev_ps = sqrt(self._C.src2dst_stddev_ps/(src2dst_packets - 1))
            self.src2dst_max_ps = self._C.src2dst_max_ps
            self.dst2src_min_ps = self._C.dst2src_min_ps
            self.dst2src_mean_ps = self._C.dst2src_mean_ps
            dst2src_packets = self.dst2src_packets
            if dst2src_packets > 1:
                self.dst2src_stddev_ps = sqrt(self._C.dst2src_stddev_ps / (dst2src_packets - 1))
            self.dst2src_max_ps = self._C.dst2src_max_ps
            self.bidirectional_min_piat_ms = self._C.bidirectional_min_piat_ms
            self.bidirectional_mean_piat_ms = self._C.bidirectional_mean_piat_ms
            if bidirectional_packets > 2:
                self.bidirectional_stddev_piat_ms = sqrt(self._C.bidirectional_stddev_piat_ms/(bidirectional_packets-2))
            self.bidirectional_max_piat_ms = self._C.bidirectional_max_piat_ms
            self.src2dst_min_piat_ms = self._C.src2dst_min_piat_ms
            self.src2dst_mean_piat_ms = self._C.src2dst_mean_piat_ms
            if src2dst_packets > 2:
                self.src2dst_stddev_piat_ms = sqrt(self._C.src2dst_stddev_piat_ms/(src2dst_packets - 2))
            self.src2dst_max_piat_ms = self._C.src2dst_max_piat_ms
            self.dst2src_min_piat_ms = self._C.dst2src_min_piat_ms
            self.dst2src_mean_piat_ms = self._C.dst2src_mean_piat_ms
            if dst2src_packets > 2:
                self.dst2src_stddev_piat_ms = sqrt(self._C.dst2src_stddev_piat_ms/(dst2src_packets - 2))
            self.dst2src_max_piat_ms = self._C.dst2src_max_piat_ms
            self.bidirectional_syn_packets = self._C.bidirectional_syn_packets
            self.bidirectional_cwr_packets = self._C.bidirectional_cwr_packets
            self.bidirectional_ece_packets = self._C.bidirectional_ece_packets
            self.bidirectional_urg_packets = self._C.bidirectional_urg_packets
            self.bidirectional_ack_packets = self._C.bidirectional_ack_packets
            self.bidirectional_psh_packets = self._C.bidirectional_psh_packets
            self.bidirectional_rst_packets = self._C.bidirectional_rst_packets
            self.bidirectional_fin_packets = self._C.bidirectional_fin_packets
            self.src2dst_syn_packets = self._C.src2dst_syn_packets
            self.src2dst_cwr_packets = self._C.src2dst_cwr_packets
            self.src2dst_ece_packets = self._C.src2dst_ece_packets
            self.src2dst_urg_packets = self._C.src2dst_urg_packets
            self.src2dst_ack_packets = self._C.src2dst_ack_packets
            self.src2dst_psh_packets = self._C.src2dst_psh_packets
            self.src2dst_rst_packets = self._C.src2dst_rst_packets
            self.src2dst_fin_packets = self._C.src2dst_fin_packets
            self.dst2src_syn_packets = self._C.dst2src_syn_packets
            self.dst2src_cwr_packets = self._C.dst2src_cwr_packets
            self.dst2src_ece_packets = self._C.dst2src_ece_packets
            self.dst2src_urg_packets = self._C.dst2src_urg_packets
            self.dst2src_ack_packets = self._C.dst2src_ack_packets
            self.dst2src_psh_packets = self._C.dst2src_psh_packets
            self.dst2src_rst_packets = self._C.dst2src_rst_packets
            self.dst2src_fin_packets = self._C.dst2src_fin_packets
        if dissect:
            if self._C.detection_completed == 1:
                self.application_name = ffi.string(self._C.application_name).decode('utf-8', errors='ignore')
                self.application_category_name = ffi.string(self._C.category_name).decode('utf-8', errors='ignore')
                self.requested_server_name = ffi.string(self._C.requested_server_name).decode('utf-8', errors='ignore')
                self.client_fingerprint = ffi.string(self._C.c_hash).decode('utf-8', errors='ignore')
                self.server_fingerprint = ffi.string(self._C.s_hash).decode('utf-8', errors='ignore')
                self.http_user_agent = ffi.string(self._C.user_agent).decode('utf-8', errors='ignore')
                self.http_content_type = ffi.string(self._C.content_type).decode('utf-8', errors='ignore')
                self.application_is_guessed = self._C.guessed

    def is_idle(self, tick, idle_timeout):
        if (tick - idle_timeout) >= self._C.bidirectional_last_seen_ms:
            return True
        else:
            return False

    def __str__(self):
        started = False
        printable = "NFEntry("
        for attr_name in self.__slots__:
            try:
                if not started:
                    printable += attr_name + "=" + str(getattr(self, attr_name))
                    started = True
                else:
                    if attr_name == 'udps':
                        for udp_name in self.udps.__dict__.keys():
                            printable += ',\n\t' + attr_name + '.' + udp_name + "=" + str(getattr(self.udps, udp_name))
                    else:
                        printable += ',\n\t' + attr_name + "=" + str(getattr(self, attr_name))
            except AttributeError:
                pass
        printable += ")"
        return printable

    def keys(self):
        ret = []
        for attr_name in self.__slots__:
            try:
                getattr(self, attr_name)
                if attr_name == 'udps':
                    for udp_name in self.udps.__dict__.keys():
                        ret.append(attr_name + '.' + udp_name)
                else:
                    ret.append(attr_name)
            except AttributeError:
                pass
        return ret

    def values(self):
        ret = []
        for attr_name in self.__slots__:
            try:
                attr_value = getattr(self, attr_name)
                if attr_name == 'udps':
                    for udp_value in self.udps.__dict__.values():
                        ret.append(udp_value)
                else:
                    ret.append(attr_value)
            except AttributeError:
                pass
        return ret



