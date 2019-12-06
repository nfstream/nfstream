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


class NFPlugin(object):
    def __init__(self, name=None, volatile=False, user_data=None):
        if name is None:
            self.name = type(self).__name__
        else:
            self.name = name
        self.user_data = user_data
        self.volatile = volatile

    def on_init(self, obs):
        return 0

    def on_update(self, obs, entry):
        pass

    def on_expire(self, entry):
        pass

    def cleanup(self):
        pass


def nfplugins_validator(plugins):
    plugin_names = []
    for plugin in plugins:
        if isinstance(plugin, NFPlugin):
            plugin_names.append(plugin.name)
        else:
            raise TypeError
    if len(plugin_names) != len(list(set(plugin_names))):
        raise ValueError


class packet_direction_setter(NFPlugin):
    """ Setter for packet direction (volatile) """
    def on_update(self, obs, entry):
        if (entry.ip_src == obs.ip_src) and (entry.src_port == obs.src_port):
            obs.close(0)
        else:
            obs.close(1)


class first_seen(NFPlugin):
    """ Timestamp in milliseconds on first flow packet """
    def on_init(self, obs):
        return obs.time


class last_seen(NFPlugin):
    """ Timestamp in milliseconds on last flow packet """
    def on_init(self, obs):
        return obs.time

    def on_update(self, obs, entry):
        entry.last_seen = obs.time


class nfhash(NFPlugin):
    """ Flow nfstream hashed value """
    def on_init(self, obs):
        return obs.nfhash


class ip_src(NFPlugin):
    """ Integer value of IP source (volatile) """
    def on_init(self, obs):
        return obs.ip_src


class ip_dst(NFPlugin):
    """ Integer value of IP source (volatile) """
    def on_init(self, obs):
        return obs.ip_dst


class version(NFPlugin):
    """ IP version """
    def on_init(self, obs):
        return obs.version


class src_port(NFPlugin):
    """ Transport layer source port """
    def on_init(self, obs):
        return obs.src_port


class dst_port(NFPlugin):
    """ Transport layer destination port """
    def on_init(self, obs):
        return obs.dst_port


class protocol(NFPlugin):
    """ Transport protocol identifier"""
    def on_init(self, obs):
        return obs.protocol


class vlan_id(NFPlugin):
    """ VLAN identifier """
    def on_init(self, obs):
        return obs.version


class src_ip(NFPlugin):
    """ String representation of ip source """
    def on_init(self, obs):
        if obs.version == 4:
            return str(ipaddress.IPv4Address(obs.ip_src))
        else:
            return str(ipaddress.IPv6Address(obs.ip_src)).replace(':0:', '::')


class dst_ip(NFPlugin):
    """ String representation of ip destination """
    def on_init(self, obs):
        if obs.version == 4:
            return str(ipaddress.IPv4Address(obs.ip_dst))
        else:
            return str(ipaddress.IPv6Address(obs.ip_dst)).replace(':0:', '::')


class total_packets(NFPlugin):
    """ Flow bidirectional packets accumulator """
    def on_init(self, obs):
        return 1

    def on_update(self, obs, entry):
        entry.total_packets += 1


class total_bytes(NFPlugin):
    """ Flow bidirectional bytes accumulator """
    def on_init(self, obs):
        return obs.length

    def on_update(self, obs, entry):
        entry.total_bytes += obs.length


class duration(NFPlugin):
    """ Flow total duration in milliseconds """
    def on_update(self, obs, entry):
        entry.duration = obs.time - entry.first_seen


class src2dst_packets(NFPlugin):
    """ Flow src -> dst packets accumulator """
    def on_init(self, obs):
        return 1

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_packets += 1


class src2dst_bytes(NFPlugin):
    """ Flow src -> dst packets accumulator """
    def on_init(self, obs):
        return obs.length

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_bytes += obs.length


class dst2src_packets(NFPlugin):
    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_packets += 1


class dst2src_bytes(NFPlugin):
    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_bytes += obs.length


class expiration_id(NFPlugin):
    """ Flow expiration ID: negative if custom, 0 if idle expiration, 1 if active expiration, 2 if natural """


def is_ndpi_proto(entry, id):
    if (entry.master_protocol == id) or (entry.app_protocol == id):
        return True
    else:
        return False


def update_ndpi_infos(entry, ndpi_flow, ndpi_protocol, ndpi):
    entry.app_protocol = ndpi_protocol.app_protocol
    entry.master_protocol = ndpi_protocol.master_protocol
    entry.application_name = ndpi.ndpi_protocol2name(ndpi_protocol)
    entry.category_name = ndpi.ndpi_category_get_name(ndpi_protocol.category)
    entry.server_info = ndpi.get_str_field(ndpi_flow.host_server_name)  # DNS and HTTP
    if is_ndpi_proto(entry, 7):  # HTTP
        entry.client_info = ndpi.get_str_field(ndpi_flow.protos.http.detected_os)
    elif is_ndpi_proto(entry, 92):  # SSH
        entry.client_info = ndpi.get_str_field(ndpi_flow.protos.ssh.client_signature)
        entry.server_info = ndpi.get_str_field(ndpi_flow.protos.ssh.server_signature)
    elif is_ndpi_proto(entry, 91) or ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_client) != '':  # TLS
        entry.client_info = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.client_certificate)
        entry.server_info = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.server_certificate)
        entry.j3a_client = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_client)
        entry.j3a_server = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_server)
    else:
        pass


class nDPI(NFPlugin):
    def on_init(self, obs):
        f = self.user_data.new_ndpi_flow()
        s = self.user_data.new_ndpi_id()
        d = self.user_data.new_ndpi_id()
        p = self.user_data.ndpi_detection_process_packet(f, obs.raw, len(obs.raw), obs.time, s, d)
        # nDPI structures are maintained in a list [ndpi_flow, ndpi_src, ndpi_dst, ndpi_proto, detection_completed]
        return [f, s, d, p, 0]

    def on_update(self, obs, entry):
        tcp_not_enough = (entry.protocol == 6) and (entry.total_packets <= self.user_data.max_tcp_dissections)
        udp_not_enough = (entry.protocol == 17) and (entry.total_packets <= self.user_data.max_udp_dissections)
        if (tcp_not_enough or udp_not_enough) and entry.nDPI[4] == 0:
            entry.nDPI[3] = self.user_data.ndpi_detection_process_packet(entry.nDPI[0],
                                                                         obs.raw,
                                                                         len(obs.raw),
                                                                         obs.time,
                                                                         entry.nDPI[1],
                                                                         entry.nDPI[2])
            update_ndpi_infos(entry, entry.nDPI[0], entry.nDPI[3], self.user_data)
        elif entry.nDPI[4] == 0:  # we reached max and still not detected
            if entry.nDPI[3].app_protocol == 0:
                entry.nDPI[3] = self.user_data.ndpi_detection_giveup(entry.nDPI[0])
                entry.nDPI[4] = 1
                update_ndpi_infos(entry, entry.nDPI[0], entry.nDPI[3], self.user_data)
        else:
            pass

    def on_expire(self, entry):
        # flow expires and we failed to detect it.
        if entry.nDPI[3].app_protocol == 0 and entry.nDPI[4] == 0:
            entry.nDPI[3] = self.user_data.ndpi_detection_giveup(entry.nDPI[0])
        update_ndpi_infos(entry, entry.nDPI[0], entry.nDPI[3], self.user_data)
        # Freeing allocated memory
        if entry.nDPI[0] != self.user_data.NULL:
            self.user_data.ndpi_flow_free(entry.nDPI[0])
            entry.nDPI[0] = self.user_data.NULL
        if entry.nDPI[1] != self.user_data.NULL:
            self.user_data.ndpi_free(entry.nDPI[1])
            entry.nDPI[1] = self.user_data.NULL
        if entry.nDPI[2] != self.user_data.NULL:
            self.user_data.ndpi_free(entry.nDPI[2])
            entry.nDPI[2] = self.user_data.NULL

    def cleanup(self):
        self.user_data.ndpi_exit_detection_module()


class app_protocol(NFPlugin):
    """ ndpi proto.app_protocol id """


class master_protocol(NFPlugin):
    """ ndpi proto.master_protocol id """


class application_name(NFPlugin):
    """ ndpi application name """
    def on_init(self, obs):
        return ''


class category_name(NFPlugin):
    """ ndpi category name """
    def on_init(self, obs):
        return ''


class client_info(NFPlugin):
    """ client dissected information """
    def on_init(self, obs):
        return ''


class server_info(NFPlugin):
    """ server dissected information """
    def on_init(self, obs):
        return ''


class j3a_client(NFPlugin):
    """ client j3a fingerprint """
    def on_init(self, obs):
        return ''


class j3a_server(NFPlugin):
    """ server j3a information """
    def on_init(self, obs):
        return ''


nfstream_core_plugins = [packet_direction_setter(volatile=True),
                         first_seen(),
                         last_seen(),
                         nfhash(volatile=True),
                         ip_src(volatile=True),
                         ip_dst(volatile=True),
                         version(),
                         src_port(),
                         dst_port(),
                         protocol(),
                         vlan_id(),
                         src_ip(),
                         dst_ip(),
                         total_packets(),
                         total_bytes(),
                         duration(),
                         src2dst_packets(),
                         src2dst_bytes(),
                         dst2src_packets(),
                         dst2src_bytes(),
                         expiration_id()
                         ]

ndpi_infos_plugins = [master_protocol(),
                      app_protocol(),
                      application_name(),
                      category_name(),
                      client_info(),
                      server_info(),
                      j3a_client(),
                      j3a_server()
                      ]
