#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lru import LRU  # for LRU streamer management
from collections import namedtuple
from .observer import Observer
import socket
from .dpi import ndpi, NDPI_PROTOCOL_BITMASK, ndpi_flow_struct, ndpi_protocol, ndpi_id_struct
from ctypes import pointer, memset, sizeof, cast, c_char_p, c_void_p, POINTER, c_uint8, addressof
max_num_udp_dissected_pkts = 16
max_num_tcp_dissected_pkts = 10

""" flow key structure """
FlowKey = namedtuple('FlowKey', ['ip_src', 'ip_dst', 'src_port', 'dst_port', 'ip_protocol'])


""" flow export str representation """
flow_export_template = '''{ip_protocol},{ip_src},{src_port},{ip_dst},{dst_port},{ndpi_proto_num},\
{src_to_dst_pkts},{src_to_dst_bytes},{dst_to_src_pkts},{dst_to_src_bytes}'''


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def emergency_callback(key, value):
    """ Callback used for Streamer eviction method """
    value.ndpi_flow = None
    print("WARNING: Streamer capacity limit reached: lru flow entry dropped.")


def get_flow_key(pkt_info):
    """ Returns a flow key from packet 5-tuple """
    if pkt_info.ip_src > pkt_info.ip_dst:
        return FlowKey(ip_src=pkt_info.ip_src, ip_dst=pkt_info.ip_dst,
                       src_port=pkt_info.src_port, dst_port=pkt_info.dst_port,
                       ip_protocol=pkt_info.ip_protocol)
    else:
        return FlowKey(ip_src=pkt_info.ip_dst, ip_dst=pkt_info.ip_src,
                       src_port=pkt_info.dst_port, dst_port=pkt_info.src_port,
                       ip_protocol=pkt_info.ip_protocol)


class Flow:
    """ Flow entry structure """
    def __init__(self, pkt_info):
        self.start_time = pkt_info.ts
        self.end_time = pkt_info.ts
        self.export_type = -1
        self.key = get_flow_key(pkt_info)
        self.ip_src = pkt_info.ip_src
        self.ip_dst = pkt_info.ip_dst
        self.__ip_src_b = pkt_info.ip_src_b
        self.__ip_dst_b = pkt_info.ip_dst_b
        self.src_port = pkt_info.src_port
        self.dst_port = pkt_info.dst_port
        self.ip_protocol = pkt_info.ip_protocol
        self.src_to_dst_pkts = 0
        self.dst_to_src_pkts = 0
        self.src_to_dst_bytes = 0
        self.dst_to_src_bytes = 0
        self.ndpi_flow = pointer(ndpi_flow_struct())
        memset(self.ndpi_flow, 0, sizeof(ndpi_flow_struct))
        self.detected_protocol = ndpi_protocol()
        self.detection_completed = 0
        self.__src_id = pointer(ndpi_id_struct())
        self.__dst_id = pointer(ndpi_id_struct())

    def debug(self):
        return flow_export_template.format(
            ip_src=inet_to_str(self.__ip_src_b).replace(':0:', '::'),
            src_port=self.src_port,
            ip_dst=inet_to_str(self.__ip_dst_b).replace(':0:', '::'),
            dst_port=self.dst_port,
            ip_protocol=self.ip_protocol,
            src_to_dst_pkts=self.src_to_dst_pkts,
            dst_to_src_pkts=self.dst_to_src_pkts,
            src_to_dst_bytes=self.src_to_dst_bytes,
            dst_to_src_bytes=self.dst_to_src_bytes,
            ndpi_proto_num=str(self.detected_protocol.master_protocol) + '.' + str(self.detected_protocol.app_protocol)
        )

    def update(self, pkt_info, active_timeout, ndpi_info_mod):
        """ Update a flow from a packet and return status """
        if (pkt_info.ts - self.end_time) >= (active_timeout*1000):
            return 2
        else:
            self.end_time = pkt_info.ts
            if (self.ip_src == pkt_info.ip_src and self.ip_dst == pkt_info.ip_dst and
                    self.src_port == pkt_info.src_port and self.dst_port == pkt_info.dst_port):
                self.src_to_dst_pkts += 1
                self.src_to_dst_bytes += pkt_info.len
            else:
                self.dst_to_src_pkts += 1
                self.dst_to_src_bytes += pkt_info.len
            if self.detection_completed == 0:
                self.detected_protocol = ndpi.ndpi_detection_process_packet(ndpi_info_mod,
                                                                            self.ndpi_flow,
                                                                            cast(cast(c_char_p(pkt_info.raw),
                                                                                      c_void_p), POINTER(c_uint8)),
                                                                            len(pkt_info.raw),
                                                                            pkt_info.ts,
                                                                            self.__src_id,
                                                                            self.__dst_id)
                valid = False
                if self.ip_protocol == 6:
                    valid = (self.src_to_dst_pkts + self.dst_to_src_pkts) > max_num_tcp_dissected_pkts
                elif self.ip_protocol == 17:
                    valid = (self.src_to_dst_pkts + self.dst_to_src_pkts) > max_num_udp_dissected_pkts
                if valid or self.detected_protocol.app_protocol != 0:
                    if valid or self.detected_protocol.master_protocol != 91:
                        self.detection_completed = 1
                        if self.detected_protocol.app_protocol == 0:
                            self.detected_protocol = ndpi.ndpi_detection_giveup(ndpi_info_mod,
                                                                                self.ndpi_flow,
                                                                                1,
                                                                                cast(addressof(c_uint8(0)),
                                                                                     POINTER(c_uint8)))
            return 0


def initialize(ndpi_struct):
    all = NDPI_PROTOCOL_BITMASK()
    ndpi.ndpi_wrap_NDPI_BITMASK_SET_ALL(pointer(all))
    ndpi.ndpi_set_protocol_detection_bitmask2(ndpi_struct, pointer(all))


class Streamer:
    """ streamer for flows management """
    num_streamers = 0

    def __init__(self, source=None, capacity=128000, active_timeout=120, inactive_timeout=60):
        Streamer.num_streamers += 1
        self.__exports = []
        self.source = source
        self.__flows = LRU(capacity, callback=emergency_callback)  # LRU cache
        self._capacity = self.__flows.get_size()  # Streamer capacity (default: 128000)
        self.active_timeout = active_timeout  # expiration active timeout
        self.inactive_timeout = inactive_timeout  # expiration inactive timeout
        self.current_flows = 0  # counter for stored flows
        self.current_tick = 0  # current timestamp
        self.processed_packets = 0  # current timestamp
        self.__inspector = ndpi.ndpi_init_detection_module()
        initialize(self.__inspector)

    def _get_capacity(self):
        """ getter for capacity attribute """
        return self.__flows.get_size()

    def _set_capacity(self, new_size):
        """ setter for capacity size attribute """
        return self.__flows.set_size(new_size)

    capacity = property(_get_capacity, _set_capacity)

    def terminate(self):
        """ terminate all entries in Streamer """
        remaining_flows = True
        while remaining_flows:
            try:
                key, value = self.__flows.peek_last_item()
                self.exporter(value, 2)
            except TypeError:
                remaining_flows = False
        ndpi.ndpi_exit_detection_module(self.__inspector)

    def exporter(self, flow, trigger_type):
        """ export method for a flow trigger_type:0(inactive), 1(active), 2(termination) """
        flow.export_type = trigger_type
        if flow.detected_protocol.app_protocol == 0:  # short unidentified use caseflows
            flow.detected_protocol = ndpi.ndpi_detection_giveup(self.__inspector,
                                                                flow.ndpi_flow,
                                                                1,
                                                                cast(addressof(c_uint8(0)),
                                                                     POINTER(c_uint8)))
            flow.detection_completed = 1

        flow.ndpi_flow = None
        del self.__flows[flow.key]
        self.current_flows -= 1
        self.__exports.append(flow)

    def inactive_watcher(self):
        """ inactive expiration management """
        remaining_inactives = True
        while remaining_inactives:
            try:
                key, value = self.__flows.peek_last_item()
                if (self.current_tick - value.end_time) >= (self.inactive_timeout*1000):
                    self.exporter(value, 0)
                else:
                    remaining_inactives = False
            except TypeError:
                remaining_inactives = False

    def active_watcher(self, key):
        """ active expiration management """
        self.exporter(self.__flows[key], 1)

    def consume(self, pkt_info):
        """ consume a packet and update Streamer status """
        self.processed_packets += 1  # increment total processed packet counter
        flow = Flow(pkt_info)
        if flow.key in self.__flows:
            flow_status = self.__flows[flow.key].update(pkt_info, self.active_timeout, self.__inspector)
            if flow_status == 2:
                self.active_watcher(flow.key)
                self.__flows[flow.key] = flow
                self.__flows[flow.key].update(pkt_info, self.active_timeout, self.__inspector)
        else:
            self.current_flows += 1
            flow.update(pkt_info, self.active_timeout, self.__inspector)
            self.__flows[flow.key] = flow
            self.current_tick = flow.start_time
            self.inactive_watcher()

    def __iter__(self):
        pkt_info_gen = Observer(source=self.source)
        for pkt_info in pkt_info_gen:
            if pkt_info is not None:
                self.consume(pkt_info)
                for export in self.__exports:
                    yield export
                self.__exports = []
        self.terminate()
        for export in self.__exports:
            yield export
        self.__exports = []


