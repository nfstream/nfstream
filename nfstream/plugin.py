#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: plugin.py
This file is part of nfstream.

Copyright (C) 2019-20 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

import math
import ipaddress


class NFPlugin(object):
    """ NFPlugin class """
    def __init__(self, name=None, volatile=False, user_data=None):
        """
        NFPlugin Parameters:
        name [default= class name]: Plugin name. Must be unique as it’s dynamically created
                                    as a flow attribute.
        volatile [default= False] : Volatile plugin is available only when flow is processed.
                                    At flow expiration level, plugin is automatically removed
                                    (will not appear as flow attribute).
        user_data [default= None] : user_data passed to the plugin. Example: external module,
                                    pickled sklearn model, etc.
        """
        if name is None:
            self.name = type(self).__name__
        else:
            self.name = name
        self.user_data = user_data
        self.volatile = volatile

    def on_init(self, obs):
        """
        on_init(self, obs): Method called at entry creation. When aggregating packets into
                            flows, this method is called on NFEntry object creation based on
                            first NFPacket object belonging to it.
        """
        return 0

    def on_update(self, obs, entry):
        """
        on_update(self, obs, entry): Method called to update each entry with its belonging obs.
                                     When aggregating packets into flows, the entry is an NFEntry
                                     object and the obs is an NFPacket object.
        """
        pass

    def on_expire(self, entry):
        """
        on_expire(self, entry):      Method called at entry expiration. When aggregating packets
                                     into flows, the entry is an NFEntry
        """
        pass

    def cleanup(self):
        """
        cleanup(self):               Method called for plugin cleanup.
        """
        pass


def nfplugins_validator(plugins):
    """ nfplugins unique names validation function """
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
        if (entry.src_ip == obs.src_ip) and (entry.src_port == obs.src_port):
            obs.close(0)
        else:
            obs.close(1)


class bidirectional_first_seen_ms(NFPlugin):
    """ Timestamp in milliseconds on first flow packet """
    def on_init(self, obs):
        return obs.time


class bidirectional_last_seen_ms(NFPlugin):
    """ Timestamp in milliseconds on last flow packet """
    def on_init(self, obs):
        return obs.time

    def on_update(self, obs, entry):
        entry.bidirectional_last_seen_ms = obs.time


class src2dst_first_seen_ms(NFPlugin):
    """ Timestamp in milliseconds on first flow packet (src -> dst direction)"""
    def on_init(self, obs):
        return obs.time


class src2dst_last_seen_ms(NFPlugin):
    """ Timestamp in milliseconds on last flow packet (src -> dst direction)"""
    def on_init(self, obs):
        return obs.time

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_last_seen_ms = obs.time


class dst2src_first_seen_ms(NFPlugin):
    """ Timestamp in milliseconds on first flow packet (dst -> src direction)"""
    def on_update(self, obs, entry):
        if obs.direction == 1 and entry.dst2src_first_seen_ms == 0:
            entry.dst2src_first_seen_ms = obs.time


class dst2src_last_seen_ms(NFPlugin):
    """ Timestamp in milliseconds on last flow packet (dst -> src direction)"""
    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_last_seen_ms = obs.time


class nfhash(NFPlugin):
    """ Flow nfstream hashed value """
    def on_init(self, obs):
        return obs.nfhash


class src_ip(NFPlugin):
    """ str value of IP source (volatile) """
    def on_init(self, obs):
        return obs.src_ip


class src_ip_type(NFPlugin):
    """ src_ip private or public """
    def on_init(self, obs):
        return int(ipaddress.ip_address(obs.src_ip).is_private)


class dst_ip_type(NFPlugin):
    """ dst_ip type: private or public """
    def on_init(self, obs):
        return int(ipaddress.ip_address(obs.dst_ip).is_private)


class dst_ip(NFPlugin):
    """ str value of IP source (volatile) """
    def on_init(self, obs):
        return obs.dst_ip


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


class bidirectional_packets(NFPlugin):
    """ Flow bidirectional packets accumulator """
    def on_init(self, obs):
        return 1

    def on_update(self, obs, entry):
        entry.bidirectional_packets += 1


class bidirectional_raw_bytes(NFPlugin):
    """ Flow bidirectional raw bytes accumulator """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        entry.bidirectional_raw_bytes += obs.raw_size


class bidirectional_ip_bytes(NFPlugin):
    """ Flow bidirectional ip bytes accumulator """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        entry.bidirectional_ip_bytes += obs.ip_size


class bidirectional_duration_ms(NFPlugin):
    """ Flow bidirectional duration in milliseconds """
    def on_update(self, obs, entry):
        entry.bidirectional_duration_ms = obs.time - entry.bidirectional_first_seen_ms


class src2dst_packets(NFPlugin):
    """ Flow src -> dst packets accumulator """
    def on_init(self, obs):
        return 1

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_packets += 1


class src2dst_raw_bytes(NFPlugin):
    """ Flow src -> dst raw bytes accumulator """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_raw_bytes += obs.raw_size


class src2dst_ip_bytes(NFPlugin):
    """ Flow src -> dst ip bytes accumulator """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_ip_bytes += obs.ip_size


class src2dst_duration_ms(NFPlugin):
    """ Flow src2dst duration in milliseconds """
    def on_update(self, obs, entry):
        entry.src2dst_duration_ms = obs.time - entry.src2dst_first_seen_ms


class dst2src_packets(NFPlugin):
    """ Flow dst2src packets accumulator """
    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_packets += 1


class dst2src_raw_bytes(NFPlugin):
    """ Flow dst -> src raw bytes accumulator """
    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_raw_bytes += obs.raw_size


class dst2src_ip_bytes(NFPlugin):
    """ Flow dst -> src ip bytes accumulator """
    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_ip_bytes += obs.ip_size


class dst2src_duration_ms(NFPlugin):
    """ Flow dst2src duration in milliseconds """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_duration_ms = obs.time - entry.dst2src_first_seen_ms


class expiration_id(NFPlugin):
    """ Flow expiration ID: negative if custom, 0 if idle expiration, 1 if active expiration, 2 if natural """


def is_ndpi_proto(entry, id):
    """ Helper to check is entry app or master protocol ids """
    if (entry.master_protocol == id) or (entry.app_protocol == id):
        return True
    else:
        return False


def update_ndpi_infos(entry, ndpi_flow, ndpi_protocol, ndpi):
    """ Updater for nDPI plugin collected informations """
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
        entry.client_info = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.client_requested_server_name)
        if ndpi_flow.protos.stun_ssl.ssl.server_names_len > 0:
            entry.server_info = ndpi.get_buffer_field(ndpi_flow.protos.stun_ssl.ssl.server_names,
                                                      ndpi_flow.protos.stun_ssl.ssl.server_names_len)
        entry.j3a_client = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_client)
        entry.j3a_server = ndpi.get_str_field(ndpi_flow.protos.stun_ssl.ssl.ja3_server)
    else:
        pass


class nDPI(NFPlugin):
    """ nDPI plugin structure (volatile) """
    def on_init(self, obs):
        f = self.user_data.new_ndpi_flow()
        s = self.user_data.new_ndpi_id()
        d = self.user_data.new_ndpi_id()
        p = self.user_data.ndpi_detection_process_packet(f, obs.ip_packet, len(obs.ip_packet), obs.time, s, d)
        # nDPI structures are maintained in a list [ndpi_flow, ndpi_src, ndpi_dst, ndpi_proto, detection_completed]
        return [f, s, d, p, 0]

    def on_update(self, obs, entry):
        tcp_not_enough = (entry.protocol == 6) and (entry.bidirectional_packets <= self.user_data.max_tcp_dissections)
        udp_not_enough = (entry.protocol == 17) and (entry.bidirectional_packets <= self.user_data.max_udp_dissections)
        if (tcp_not_enough or udp_not_enough) and entry.nDPI[4] == 0:
            entry.nDPI[3] = self.user_data.ndpi_detection_process_packet(entry.nDPI[0],
                                                                         obs.ip_packet,
                                                                         len(obs.ip_packet),
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


class bidirectional_piat(NFPlugin):
    """ Flow bidirectional packet inter arrival time """
    def on_init(self, obs):
        return [-1, obs.time]  # [iat value, last packet timestamp]

    def on_update(self, obs, entry):
        entry.bidirectional_piat = [obs.time - entry.bidirectional_piat[1], obs.time]


class src2dst_piat(NFPlugin):
    """ Flow src -> dst packet inter arrival time """
    def on_init(self, obs):
        if obs.direction == 0:
            return [-1, obs.time]  # [iat value, last packet timestamp]
        else:
            return [-1, -1]

    def on_update(self, obs, entry):
        if obs.direction == 0:
            if entry.src2dst_piat[1] == -1:
                entry.src2dst_piat = [-1, obs.time]
            else:
                entry.src2dst_piat = [obs.time - entry.src2dst_piat[1], obs.time]


class dst2src_piat(NFPlugin):
    """ Flow dst -> src packet inter arrival time """
    def on_init(self, obs):
        if obs.direction == 1:
            return [-1, obs.time]  # [iat value, last packet timestamp]
        else:
            return [-1, -1]

    def on_update(self, obs, entry):
        if obs.direction == 1:
            if entry.dst2src_piat[1] == -1:
                entry.dst2src_piat = [-1, obs.time]
            else:
                entry.dst2src_piat = [obs.time - entry.dst2src_piat[1], obs.time]


class bidirectional_max_piat_ms(NFPlugin):
    """ Flow bidirectional maximum packet inter arrival time """
    def on_init(self, obs):
        return -1  # we will set it as -1 as init value

    def on_update(self, obs, entry):
        if entry.bidirectional_max_piat_ms == -1 and entry.bidirectional_piat[0] >= 0:
            entry.bidirectional_max_piat_ms = entry.bidirectional_piat[0]
        if entry.bidirectional_piat[0] > entry.bidirectional_max_piat_ms:
            entry.bidirectional_max_piat_ms = entry.bidirectional_piat[0]


class bidirectional_weldord_piat_ms(NFPlugin):
    """ Flow bidirectional packet inter arrival time welford algorithm structure (volatile) """
    def on_init(self, obs):
        return [0, 0, 0]

    def on_update(self, obs, entry):
        if entry.bidirectional_piat[0] >= 0:
            k = entry.bidirectional_weldord_piat_ms[0] + 1
            entry.bidirectional_weldord_piat_ms[0] = k
            m = entry.bidirectional_weldord_piat_ms[1]
            s = entry.bidirectional_weldord_piat_ms[2]
            entry.bidirectional_weldord_piat_ms[1] = \
                m + (entry.bidirectional_piat[0] - m) * 1. / entry.bidirectional_weldord_piat_ms[0]
            entry.bidirectional_weldord_piat_ms[2] = \
                s + (entry.bidirectional_piat[0] - m) * \
                (entry.bidirectional_piat[0] - entry.bidirectional_weldord_piat_ms[1])


class bidirectional_mean_piat_ms(NFPlugin):
    """ Flow bidirectional mean packet inter arrival time """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if entry.bidirectional_piat[0] >= 0:
            entry.bidirectional_mean_piat_ms = entry.bidirectional_weldord_piat_ms[1]


class bidirectional_stdev_piat_ms(NFPlugin):
    """ Flow bidirectional packet inter arrival time standard deviation (sample stddev)"""
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if entry.bidirectional_piat[0] >= 0:
            if entry.bidirectional_weldord_piat_ms[0] == 1:
                entry.bidirectional_stdev_piat_ms = 0
            else:
                entry.bidirectional_stdev_piat_ms = math.sqrt(
                    entry.bidirectional_weldord_piat_ms[2]/(entry.bidirectional_weldord_piat_ms[0] - 1)
                )


class bidirectional_min_piat_ms(NFPlugin):
    """ Flow bidirectional minimum packet inter arrival time """
    def on_init(self, obs):
        return -1  # we will set it as -1 as init value

    def on_update(self, obs, entry):
        if entry.bidirectional_min_piat_ms == -1 and entry.bidirectional_piat[0] >= 0:
            entry.bidirectional_min_piat_ms = entry.bidirectional_piat[0]
        if entry.bidirectional_piat[0] < entry.bidirectional_min_piat_ms:
            entry.bidirectional_min_piat_ms = entry.bidirectional_piat[0]


class src2dst_max_piat_ms(NFPlugin):
    """ Flow src -> dst maximum packet inter arrival time """
    def on_init(self, obs):
        return -1  # we will set it as -1 as init value

    def on_update(self, obs, entry):
        if obs.direction == 0:
            if entry.src2dst_max_piat_ms == -1 and entry.src2dst_piat[0] >= 0:
                entry.src2dst_max_piat_ms = entry.src2dst_piat[0]
            if entry.src2dst_piat[0] > entry.src2dst_max_piat_ms:
                entry.src2dst_max_piat_ms = entry.src2dst_piat[0]


class src2dst_min_piat_ms(NFPlugin):
    """ Flow src -> dst minimum packet inter arrival time """
    def on_init(self, obs):
        return -1  # we will set it as -1 as init value

    def on_update(self, obs, entry):
        if obs.direction == 0:
            if entry.src2dst_min_piat_ms == -1 and entry.src2dst_piat[0] >= 0:
                entry.src2dst_min_piat_ms = entry.src2dst_piat[0]
            if entry.src2dst_piat[0] < entry.src2dst_min_piat_ms:
                entry.src2dst_min_piat_ms = entry.src2dst_piat[0]


class src2dst_weldord_piat_ms(NFPlugin):
    """ Flow src -> dst packet inter arrival time welford algorithm structure (volatile) """
    def on_init(self, obs):
        return [0, 0, 0]

    def on_update(self, obs, entry):
        if obs.direction == 0 and entry.src2dst_piat[0] >= 0:
            k = entry.src2dst_weldord_piat_ms[0] + 1
            entry.src2dst_weldord_piat_ms[0] = k
            m = entry.src2dst_weldord_piat_ms[1]
            s = entry.src2dst_weldord_piat_ms[2]
            entry.src2dst_weldord_piat_ms[1] = m + (entry.src2dst_piat[0] - m) * 1. / entry.src2dst_weldord_piat_ms[0]
            entry.src2dst_weldord_piat_ms[2] = s + (entry.src2dst_piat[0] - m) * (entry.src2dst_piat[0] -
                                                                                  entry.src2dst_weldord_piat_ms[1])


class src2dst_mean_piat_ms(NFPlugin):
    """ Flow src -> dst mean packet inter arrival time """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 0 and entry.src2dst_piat[0] >= 0:
            entry.src2dst_mean_piat_ms = entry.src2dst_weldord_piat_ms[1]


class src2dst_stdev_piat_ms(NFPlugin):
    """ Flow src -> dst packet inter arrival time standard deviation (sample stdev)"""
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1 and entry.src2dst_piat[0] >= 0:
            if entry.src2dst_weldord_piat_ms[0] == 1:
                entry.src2dst_stdev_piat_ms = 0
            else:
                entry.src2dst_stdev_piat_ms = math.sqrt(
                    entry.src2dst_weldord_piat_ms[2]/(entry.src2dst_weldord_piat_ms[0] - 1)
                )


class dst2src_max_piat_ms(NFPlugin):
    """ Flow dst -> src maximum packet inter arrival time """
    def on_init(self, obs):
        return -1  # we will set it as -1 as init value

    def on_update(self, obs, entry):
        if obs.direction == 0:
            if entry.dst2src_max_piat_ms == -1 and entry.dst2src_piat[0] >= 0:
                entry.dst2src_max_piat_ms = entry.dst2src_piat[0]
            if entry.dst2src_piat[0] > entry.dst2src_max_piat_ms:
                entry.dst2src_max_piat_ms = entry.dst2src_piat[0]


class dst2src_weldord_piat_ms(NFPlugin):
    """ Flow dst -> src packet inter arrival time welford algorithm structure (volatile) """
    def on_init(self, obs):
        return [0, 0, 0]

    def on_update(self, obs, entry):
        if obs.direction == 1 and entry.dst2src_piat[0] >= 0:
            k = entry.dst2src_weldord_piat_ms[0] + 1
            entry.dst2src_weldord_piat_ms[0] = k
            m = entry.dst2src_weldord_piat_ms[1]
            s = entry.dst2src_weldord_piat_ms[2]
            entry.dst2src_weldord_piat_ms[1] = m + (entry.dst2src_piat[0] - m) * 1. / entry.dst2src_weldord_piat_ms[0]
            entry.dst2src_weldord_piat_ms[2] = s + (entry.dst2src_piat[0] - m) * (entry.dst2src_piat[0] -
                                                                                  entry.dst2src_weldord_piat_ms[1])


class dst2src_mean_piat_ms(NFPlugin):
    """ Flow dst -> src mean packet inter arrival time """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1 and entry.dst2src_piat[0] >= 0:
            entry.dst2src_mean_piat_ms = entry.dst2src_weldord_piat_ms[1]


class dst2src_stdev_piat_ms(NFPlugin):
    """ Flow dst -> src packet inter arrival time standard deviation (sample stdev)"""
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1 and entry.dst2src_piat[0] >= 0:
            if entry.dst2src_weldord_piat_ms[0] == 1:
                entry.dst2src_stdev_piat_ms = 0
            else:
                entry.dst2src_stdev_piat_ms = math.sqrt(
                    entry.dst2src_weldord_piat_ms[2]/(entry.dst2src_weldord_piat_ms[0] - 1)
                )


class dst2src_min_piat_ms(NFPlugin):
    """ Flow dst -> src minimum packet inter arrival time """
    def on_init(self, obs):
        return -1  # we will set it as -1 as init value

    def on_update(self, obs, entry):
        if obs.direction == 1:
            if entry.dst2src_min_piat_ms == -1 and entry.dst2src_piat[0] >= 0:
                entry.dst2src_min_piat_ms = entry.dst2src_piat[0]
            if entry.dst2src_piat[0] < entry.dst2src_min_piat_ms:
                entry.dst2src_min_piat_ms = entry.dst2src_piat[0]


class bidirectional_min_raw_ps(NFPlugin):
    """ Flow bidirectional minimum raw packet size """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        if obs.raw_size < entry.bidirectional_min_raw_ps:
            entry.bidirectional_min_raw_ps = obs.raw_size


class bidirectional_weldord_raw_ps(NFPlugin):
    """ Flow bidirectional raw packet size welford algorithm structure (volatile)"""
    def on_init(self, obs):
        return [1, obs.raw_size, 0]

    def on_update(self, obs, entry):
        k = entry.bidirectional_weldord_raw_ps[0] + 1
        entry.bidirectional_weldord_raw_ps[0] = k
        m = entry.bidirectional_weldord_raw_ps[1]
        s = entry.bidirectional_weldord_raw_ps[2]
        entry.bidirectional_weldord_raw_ps[1] = \
            m + (obs.raw_size - m) * 1. / entry.bidirectional_weldord_raw_ps[0]
        entry.bidirectional_weldord_raw_ps[2] = \
            s + (obs.raw_size - m) * (obs.raw_size - entry.bidirectional_weldord_raw_ps[1])


class bidirectional_mean_raw_ps(NFPlugin):
    """ Flow bidirectional mean raw packet size """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        entry.bidirectional_mean_raw_ps = entry.bidirectional_weldord_raw_ps[1]


class bidirectional_stdev_raw_ps(NFPlugin):
    """ Flow bidirectional raw packet size standard deviation (sample stddev) """
    def on_init(self, obs):
        return 0

    def on_update(self, obs, entry):
        entry.bidirectional_stdev_raw_ps = \
            math.sqrt(entry.bidirectional_weldord_raw_ps[2]/(entry.bidirectional_weldord_raw_ps[0] - 1))


class bidirectional_max_raw_ps(NFPlugin):
    """ Flow bidirectional maximum raw packet size """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        if obs.raw_size > entry.bidirectional_max_raw_ps:
            entry.bidirectional_max_raw_ps = obs.raw_size


class src2dst_min_raw_ps(NFPlugin):
    """ Flow src -> dst minimum raw packet size """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        if obs.raw_size < entry.src2dst_min_raw_ps and obs.direction == 0:
            entry.src2dst_min_raw_ps = obs.raw_size


class src2dst_weldord_raw_ps(NFPlugin):
    """ Flow src -> dst raw packet size welford algorithm structure (volatile) """
    def on_init(self, obs):
        return [1, obs.raw_size, 0]

    def on_update(self, obs, entry):
        if obs.direction == 0:
            k = entry.src2dst_weldord_raw_ps[0] + 1
            entry.src2dst_weldord_raw_ps[0] = k
            m = entry.src2dst_weldord_raw_ps[1]
            s = entry.src2dst_weldord_raw_ps[2]
            entry.src2dst_weldord_raw_ps[1] = \
                m + (obs.raw_size - m) * 1. / entry.src2dst_weldord_raw_ps[0]
            entry.src2dst_weldord_raw_ps[2] = \
                s + (obs.raw_size - m) * (obs.raw_size - entry.src2dst_weldord_raw_ps[1])


class src2dst_mean_raw_ps(NFPlugin):
    """ Flow src -> dst mean raw packet size """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_mean_raw_ps = entry.src2dst_weldord_raw_ps[1]


class src2dst_stdev_raw_ps(NFPlugin):
    """ Flow src -> dst raw packet size standard deviation (sample stdev)"""
    def on_init(self, obs):
        return 0

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_stdev_raw_ps = \
                math.sqrt(entry.src2dst_weldord_raw_ps[2]/(entry.src2dst_weldord_raw_ps[0] - 1))


class src2dst_max_raw_ps(NFPlugin):
    """ Flow src -> dst maximum raw packet size """
    def on_init(self, obs):
        return obs.raw_size

    def on_update(self, obs, entry):
        if obs.raw_size > entry.src2dst_max_raw_ps and obs.direction == 0:
            entry.src2dst_max_raw_ps = obs.raw_size


class dst2src_min_raw_ps(NFPlugin):
    """ Flow dst -> src minimum raw packet size """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if entry.dst2src_min_raw_ps == -1 and obs.direction == 1:
            entry.dst2src_min_raw_ps = obs.raw_size
        if obs.raw_size < entry.dst2src_min_raw_ps and obs.direction == 1:
            entry.dst2src_min_raw_ps = obs.raw_size


class dst2src_weldord_raw_ps(NFPlugin):
    """ Flow dst -> src  raw packet size welford algorithm structure (volatile)"""
    def on_init(self, obs):
        return [0, 0, 0]

    def on_update(self, obs, entry):
        if obs.direction == 1:
            k = entry.dst2src_weldord_raw_ps[0] + 1
            entry.dst2src_weldord_raw_ps[0] = k
            m = entry.dst2src_weldord_raw_ps[1]
            s = entry.dst2src_weldord_raw_ps[2]
            entry.dst2src_weldord_raw_ps[1] = \
                m + (obs.raw_size - m) * 1. / entry.dst2src_weldord_raw_ps[0]
            entry.dst2src_weldord_raw_ps[2] = \
                s + (obs.raw_size - m) * (obs.raw_size - entry.dst2src_weldord_raw_ps[1])


class dst2src_mean_raw_ps(NFPlugin):
    """ Flow dst -> src mean raw packet size """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_mean_raw_ps = entry.dst2src_weldord_raw_ps[1]


class dst2src_stdev_raw_ps(NFPlugin):
    """ Flow dst -> src raw packet size standard deviation (sample stdev) """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1:
            if entry.dst2src_weldord_raw_ps[0] == 1:
                entry.dst2src_stdev_raw_ps = 0
            else:
                entry.dst2src_stdev_raw_ps = \
                    math.sqrt(entry.dst2src_weldord_raw_ps[2]/(entry.dst2src_weldord_raw_ps[0] - 1))


class dst2src_max_raw_ps(NFPlugin):
    """ Flow dst -> src maximum raw packet size """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.raw_size > entry.dst2src_max_raw_ps and obs.direction == 1:
            entry.dst2src_max_raw_ps = obs.raw_size


class bidirectional_min_ip_ps(NFPlugin):
    """ Flow bidirectional minimum ip packet size """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        if obs.ip_size < entry.bidirectional_min_ip_ps:
            entry.bidirectional_min_ip_ps = obs.ip_size


class bidirectional_weldord_ip_ps(NFPlugin):
    """ Flow bidirectional ip packet size welford algorithm structure (volatile) """
    def on_init(self, obs):
        return [1, obs.ip_size, 0]

    def on_update(self, obs, entry):
        k = entry.bidirectional_weldord_ip_ps[0] + 1
        entry.bidirectional_weldord_ip_ps[0] = k
        m = entry.bidirectional_weldord_ip_ps[1]
        s = entry.bidirectional_weldord_ip_ps[2]
        entry.bidirectional_weldord_ip_ps[1] = \
            m + (obs.ip_size - m) * 1. / entry.bidirectional_weldord_ip_ps[0]
        entry.bidirectional_weldord_ip_ps[2] = \
            s + (obs.ip_size - m) * (obs.ip_size - entry.bidirectional_weldord_ip_ps[1])


class bidirectional_mean_ip_ps(NFPlugin):
    """ Flow bidirectional mean ip packet size """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        entry.bidirectional_mean_ip_ps = entry.bidirectional_weldord_ip_ps[1]


class bidirectional_stdev_ip_ps(NFPlugin):
    """ Flow bidirectional ip packet size standard deviation (sample stdev) """
    def on_init(self, obs):
        return 0

    def on_update(self, obs, entry):
        entry.bidirectional_stdev_ip_ps = \
            math.sqrt(entry.bidirectional_weldord_ip_ps[2]/(entry.bidirectional_weldord_ip_ps[0] - 1))


class bidirectional_max_ip_ps(NFPlugin):
    """ Flow bidirectional maximum ip packet size """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        if obs.ip_size > entry.bidirectional_max_ip_ps:
            entry.bidirectional_max_ip_ps = obs.ip_size


class src2dst_min_ip_ps(NFPlugin):
    """ Flow src -> dst minimum ip packet size """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        if obs.ip_size < entry.src2dst_min_ip_ps and obs.direction == 0:
            entry.src2dst_min_ip_ps = obs.ip_size


class src2dst_weldord_ip_ps(NFPlugin):
    """ Flow src -> dst ip packet size welford algorithm structure (volatile) """
    def on_init(self, obs):
        return [1, obs.ip_size, 0]

    def on_update(self, obs, entry):
        if obs.direction == 0:
            k = entry.src2dst_weldord_ip_ps[0] + 1
            entry.src2dst_weldord_ip_ps[0] = k
            m = entry.src2dst_weldord_ip_ps[1]
            s = entry.src2dst_weldord_ip_ps[2]
            entry.src2dst_weldord_ip_ps[1] = \
                m + (obs.ip_size - m) * 1. / entry.src2dst_weldord_ip_ps[0]
            entry.src2dst_weldord_ip_ps[2] = \
                s + (obs.ip_size - m) * (obs.ip_size - entry.src2dst_weldord_ip_ps[1])


class src2dst_mean_ip_ps(NFPlugin):
    """ Flow src -> dst mean ip packet size """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_mean_ip_ps = entry.src2dst_weldord_ip_ps[1]


class src2dst_stdev_ip_ps(NFPlugin):
    """ Flow src -> dst ip packet size standard deviation (sample stdev) """
    def on_init(self, obs):
        return 0

    def on_update(self, obs, entry):
        if obs.direction == 0:
            entry.src2dst_stdev_ip_ps = \
                math.sqrt(entry.src2dst_weldord_ip_ps[2]/(entry.src2dst_weldord_ip_ps[0] - 1))


class src2dst_max_ip_ps(NFPlugin):
    """ Flow src -> dst maximum ip packet size """
    def on_init(self, obs):
        return obs.ip_size

    def on_update(self, obs, entry):
        if obs.ip_size > entry.src2dst_max_ip_ps and obs.direction == 0:
            entry.src2dst_max_ip_ps = obs.ip_size


class dst2src_min_ip_ps(NFPlugin):
    """ Flow dst -> src minimum ip packet size """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if entry.dst2src_min_ip_ps == -1 and obs.direction == 1:
            entry.dst2src_min_ip_ps = obs.ip_size
        if obs.ip_size < entry.dst2src_min_ip_ps and obs.direction == 1:
            entry.dst2src_min_ip_ps = obs.ip_size


class dst2src_weldord_ip_ps(NFPlugin):
    """ Flow dst -> src ip packet size welford algorithm structure (volatile) """
    def on_init(self, obs):
        return [0, 0, 0]

    def on_update(self, obs, entry):
        if obs.direction == 1:
            k = entry.dst2src_weldord_ip_ps[0] + 1
            entry.dst2src_weldord_ip_ps[0] = k
            m = entry.dst2src_weldord_ip_ps[1]
            s = entry.dst2src_weldord_ip_ps[2]
            entry.dst2src_weldord_ip_ps[1] = \
                m + (obs.ip_size - m) * 1. / entry.dst2src_weldord_ip_ps[0]
            entry.dst2src_weldord_ip_ps[2] = \
                s + (obs.ip_size - m) * (obs.ip_size - entry.dst2src_weldord_ip_ps[1])


class dst2src_mean_ip_ps(NFPlugin):
    """ Flow dst -> src mean ip packet size """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1:
            entry.dst2src_mean_ip_ps = entry.dst2src_weldord_ip_ps[1]


class dst2src_stdev_ip_ps(NFPlugin):
    """ Flow dst -> src ip packet size standard deviation (sample stdev) """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.direction == 1:
            if entry.dst2src_weldord_ip_ps[0] == 1:
                entry.dst2src_stdev_ip_ps = 0
            else:
                entry.dst2src_stdev_ip_ps = \
                    math.sqrt(entry.dst2src_weldord_ip_ps[2]/(entry.dst2src_weldord_ip_ps[0] - 1))


class dst2src_max_ip_ps(NFPlugin):
    """ Flow dst -> src maximum ip packet size """
    def on_init(self, obs):
        return -1

    def on_update(self, obs, entry):
        if obs.ip_size > entry.dst2src_max_ip_ps and obs.direction == 1:
            entry.dst2src_max_ip_ps = obs.ip_size


class bidirectional_syn_packets(NFPlugin):
    """ Flow bidirectional syn packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.syn == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.syn == 1:
            entry.bidirectional_syn_packets += 1


class bidirectional_cwr_packets(NFPlugin):
    """ Flow bidirectional cwr packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.cwr == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.cwr == 1:
            entry.bidirectional_cwr_packets += 1


class bidirectional_ece_packets(NFPlugin):
    """ Flow bidirectional ece packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.ece == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.ece == 1:
            entry.bidirectional_ece_packets += 1


class bidirectional_urg_packets(NFPlugin):
    """ Flow bidirectional urg packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.urg == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.urg == 1:
            entry.bidirectional_urg_packets += 1


class bidirectional_ack_packets(NFPlugin):
    """ Flow bidirectional ack packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.ack == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.ack == 1:
            entry.bidirectional_ack_packets += 1


class bidirectional_psh_packets(NFPlugin):
    """ Flow bidirectional psh packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.psh == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.psh == 1:
            entry.bidirectional_psh_packets += 1


class bidirectional_rst_packets(NFPlugin):
    """ Flow bidirectional rst packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.rst == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.rst == 1:
            entry.bidirectional_rst_packets += 1


class bidirectional_fin_packets(NFPlugin):
    """ Flow bidirectional fin packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.fin == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.tcpflags.fin == 1:
            entry.bidirectional_fin_packets += 1

class src2dst_syn_packets(NFPlugin):
    """ Flow src2dst syn packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.syn == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.syn == 1:
            entry.src2dst_syn_packets += 1


class src2dst_cwr_packets(NFPlugin):
    """ Flow src2dst cwr packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.cwr == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.cwr == 1:
            entry.src2dst_cwr_packets += 1


class src2dst_ece_packets(NFPlugin):
    """ Flow src2dst ece packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.ece == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.ece == 1:
            entry.src2dst_ece_packets += 1


class src2dst_urg_packets(NFPlugin):
    """ Flow src2dst urg packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.urg == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.urg == 1:
            entry.src2dst_urg_packets += 1


class src2dst_ack_packets(NFPlugin):
    """ Flow src2dst ack packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.ack == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.ack == 1:
            entry.src2dst_ack_packets += 1


class src2dst_psh_packets(NFPlugin):
    """ Flow src2dst psh packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.psh == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.psh == 1:
            entry.src2dst_psh_packets += 1


class src2dst_rst_packets(NFPlugin):
    """ Flow src2dst rst packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.rst == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.rst == 1:
            entry.src2dst_rst_packets += 1


class src2dst_fin_packets(NFPlugin):
    """ Flow src2dst fin packet accumulators """
    def on_init(self, obs):
        if obs.tcpflags.fin == 1:
            return 1
        else:
            return 0

    def on_update(self, obs, entry):
        if obs.direction == 0 and obs.tcpflags.fin == 1:
            entry.src2dst_fin_packets += 1


class dst2src_syn_packets(NFPlugin):
    """ Flow dst2src syn packet accumulators """
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.syn == 1:
            entry.dst2src_syn_packets += 1


class dst2src_cwr_packets(NFPlugin):
    """ Flow dst2src cwr packet accumulators """
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.cwr == 1:
            entry.dst2src_cwr_packets += 1


class dst2src_ece_packets(NFPlugin):
    """ Flow dst2src ece packet accumulators """
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.ece == 1:
            entry.dst2src_ece_packets += 1


class dst2src_urg_packets(NFPlugin):
    """ Flow dst2src urg packet accumulators """
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.urg == 1:
            entry.dst2src_urg_packets += 1


class dst2src_ack_packets(NFPlugin):
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.ack == 1:
            entry.dst2src_ack_packets += 1


class dst2src_psh_packets(NFPlugin):
    """ Flow dst2src psh packet accumulators """
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.psh == 1:
            entry.dst2src_psh_packets += 1


class dst2src_rst_packets(NFPlugin):
    """ Flow dst2src rst packet accumulators """
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.rst == 1:
            entry.dst2src_rst_packets += 1


class dst2src_fin_packets(NFPlugin):
    """ Flow dst2src fin packet accumulators """
    def on_update(self, obs, entry):
        if obs.direction == 1 and obs.tcpflags.fin == 1:
            entry.dst2src_fin_packets += 1


"""--------------------------------- nfstream core plugins ----------------------------------------------------------"""
nfstream_core_plugins = [packet_direction_setter(volatile=True),
                         bidirectional_first_seen_ms(),
                         bidirectional_last_seen_ms(),
                         src2dst_first_seen_ms(),
                         src2dst_last_seen_ms(),
                         dst2src_first_seen_ms(),
                         dst2src_last_seen_ms(),
                         nfhash(volatile=True),
                         src_ip(),
                         src_ip_type(),
                         dst_ip(),
                         dst_ip_type(),
                         version(),
                         src_port(),
                         dst_port(),
                         protocol(),
                         vlan_id(),
                         bidirectional_packets(),
                         bidirectional_raw_bytes(),
                         bidirectional_ip_bytes(),
                         bidirectional_duration_ms(),
                         src2dst_packets(),
                         src2dst_raw_bytes(),
                         src2dst_ip_bytes(),
                         src2dst_duration_ms(),
                         dst2src_packets(),
                         dst2src_raw_bytes(),
                         dst2src_ip_bytes(),
                         dst2src_duration_ms(),
                         expiration_id()
                         ]


"""--------------------------------- nfstream statistical plugins ---------------------------------------------------"""
nfstream_statistical_plugins = [bidirectional_min_raw_ps(),
                                bidirectional_weldord_raw_ps(volatile=True),
                                bidirectional_mean_raw_ps(),
                                bidirectional_stdev_raw_ps(),
                                bidirectional_max_raw_ps(),
                                src2dst_min_raw_ps(),
                                src2dst_weldord_raw_ps(volatile=True),
                                src2dst_mean_raw_ps(),
                                src2dst_stdev_raw_ps(),
                                src2dst_max_raw_ps(),
                                dst2src_min_raw_ps(),
                                dst2src_weldord_raw_ps(volatile=True),
                                dst2src_mean_raw_ps(),
                                dst2src_stdev_raw_ps(),
                                dst2src_max_raw_ps(),
                                bidirectional_min_ip_ps(),
                                bidirectional_weldord_ip_ps(volatile=True),
                                bidirectional_mean_ip_ps(),
                                bidirectional_stdev_ip_ps(),
                                bidirectional_max_ip_ps(),
                                src2dst_min_ip_ps(),
                                src2dst_weldord_ip_ps(volatile=True),
                                src2dst_mean_ip_ps(),
                                src2dst_stdev_ip_ps(),
                                src2dst_max_ip_ps(),
                                dst2src_min_ip_ps(),
                                dst2src_weldord_ip_ps(volatile=True),
                                dst2src_mean_ip_ps(),
                                dst2src_stdev_ip_ps(),
                                dst2src_max_ip_ps(),
                                bidirectional_piat(volatile=True),
                                src2dst_piat(volatile=True),
                                dst2src_piat(volatile=True),
                                bidirectional_min_piat_ms(),
                                bidirectional_weldord_piat_ms(volatile=True),
                                bidirectional_mean_piat_ms(),
                                bidirectional_stdev_piat_ms(),
                                bidirectional_max_piat_ms(),
                                src2dst_min_piat_ms(),
                                src2dst_weldord_piat_ms(volatile=True),
                                src2dst_mean_piat_ms(),
                                src2dst_stdev_piat_ms(),
                                src2dst_max_piat_ms(),
                                dst2src_min_piat_ms(),
                                dst2src_weldord_piat_ms(volatile=True),
                                dst2src_mean_piat_ms(),
                                dst2src_stdev_piat_ms(),
                                dst2src_max_piat_ms(),
                                bidirectional_syn_packets(),
                                bidirectional_cwr_packets(),
                                bidirectional_ece_packets(),
                                bidirectional_urg_packets(),
                                bidirectional_ack_packets(),
                                bidirectional_psh_packets(),
                                bidirectional_rst_packets(),
                                bidirectional_fin_packets(),
                                src2dst_syn_packets(),
                                src2dst_cwr_packets(),
                                src2dst_ece_packets(),
                                src2dst_urg_packets(),
                                src2dst_ack_packets(),
                                src2dst_psh_packets(),
                                src2dst_rst_packets(),
                                src2dst_fin_packets(),
                                dst2src_syn_packets(),
                                dst2src_cwr_packets(),
                                dst2src_ece_packets(),
                                dst2src_urg_packets(),
                                dst2src_ack_packets(),
                                dst2src_psh_packets(),
                                dst2src_rst_packets(),
                                dst2src_fin_packets()
                                ]

"""--------------------------------- nfstream nDPI plugins ----------------------------------------------------------"""
ndpi_infos_plugins = [master_protocol(),
                      app_protocol(),
                      application_name(),
                      category_name(),
                      client_info(),
                      server_info(),
                      j3a_client(),
                      j3a_server()
                      ]
