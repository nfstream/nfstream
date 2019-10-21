#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lru import LRU  # for LRU streamer management
from collections import namedtuple
from .observer import Observer
from .classifier import NDPIClassifier, NFStreamClassifier
import socket
import json

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
    if 'ndpi' in list(value.classifiers.keys()):
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
    def __init__(self, pkt_info, streamer_classifiers, streamer_metrics):
        self.start_time = pkt_info.ts
        self.end_time = pkt_info.ts
        self.export_reason = -1
        self.key = get_flow_key(pkt_info)
        self.__ip_src_int = pkt_info.ip_src
        self.__ip_dst_int = pkt_info.ip_dst
        self.__ip_src_b = pkt_info.ip_src_b
        self.__ip_dst_b = pkt_info.ip_dst_b
        self.ip_src = inet_to_str(self.__ip_src_b)
        self.ip_dst = inet_to_str(self.__ip_dst_b)
        self.src_port = pkt_info.src_port
        self.dst_port = pkt_info.dst_port
        self.ip_protocol = pkt_info.ip_protocol
        self.src_to_dst_pkts = 0
        self.dst_to_src_pkts = 0
        self.src_to_dst_bytes = 0
        self.dst_to_src_bytes = 0
        self.metrics = {}
        self.classifiers = {}
        for metric_name in list(streamer_metrics.keys()):
            self.metrics[metric_name] = 0
        for name, classifier in streamer_classifiers.items():
            self.classifiers[classifier.name] = {}
            classifier.on_flow_init(self)

    def update(self, pkt_info, active_timeout, streamer_classifiers, streamer_metrics):
        """ Update a flow from a packet and return status """
        if (pkt_info.ts - self.end_time) >= (active_timeout*1000):  # Active Expiration
            return 1
        else:  # We start by core management
            self.end_time = pkt_info.ts
            if (self.__ip_src_int == pkt_info.ip_src and self.__ip_dst_int == pkt_info.ip_dst and
                    self.src_port == pkt_info.src_port and self.dst_port == pkt_info.dst_port):
                self.src_to_dst_pkts += 1
                self.src_to_dst_bytes += pkt_info.size
                pkt_info.direction = 0
            else:
                self.dst_to_src_pkts += 1
                self.dst_to_src_bytes += pkt_info.size
                pkt_info.direction = 1

            for name, classifier in streamer_classifiers.items():
                classifier.on_flow_update(pkt_info, self)

            metrics_names = list(streamer_metrics.keys())
            for metric_name in metrics_names:
                self.metrics[metric_name] = streamer_metrics[metric_name](pkt_info, self)

            return self.export_reason

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
            ndpi_proto_num=str(self.classifiers['ndpi']['master_id']) + '.' + str(self.classifiers['ndpi']['app_id'])
        )

    def __str__(self):
        metrics = {'ip_src': self.ip_src,
                   'src_port': self.src_port,
                   'ip_dst': self.ip_dst,
                   'dst_port': self.dst_port,
                   'ip_protocol': self.ip_protocol,
                   'src_to_dst_pkts': self.src_to_dst_pkts,
                   'dst_to_src_pkts': self.dst_to_src_pkts,
                   'src_to_dst_bytes': self.src_to_dst_bytes,
                   'dst_to_src_bytes': self.dst_to_src_bytes,
                   'start_time': self.start_time,
                   'end_time': self.end_time,
                   'export_reason': self.export_reason
                   }
        return json.dumps({**self.metrics, **metrics})


class Streamer:
    """ streamer for flows management """
    num_streamers = 0

    def __init__(self, source=None, capacity=128000, active_timeout=120, inactive_timeout=60,
                 user_metrics=None, user_classifiers=None, enable_ndpi=True):

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
        self.user_classifiers = {}
        if user_classifiers is not None:
            try:
                classifier_iterator = iter(user_classifiers)
                for classifier in classifier_iterator:
                    if isinstance(classifier, NFStreamClassifier):
                        self.user_classifiers[classifier.name] = classifier
            except TypeError:
                self.user_classifiers[user_classifiers.name] = user_classifiers
        self.user_metrics = {}
        if enable_ndpi:
            ndpi_classifier = NDPIClassifier('ndpi')
            self.user_classifiers[ndpi_classifier.name] = ndpi_classifier
        if user_metrics is not None:
            self.user_metrics = user_metrics

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
                value.export_reason = 2
                self.exporter(value)
            except TypeError:
                remaining_flows = False

        for classifier_name, classifier in self.user_classifiers.items():
            self.user_classifiers[classifier_name].on_exit()

    def exporter(self, flow):
        """ export method for a flow trigger_type:0(inactive), 1(active), 2(flush) """
        for classifier_name, classifier in self.user_classifiers.items():
            self.user_classifiers[classifier_name].on_flow_terminate(flow)
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
                    value.export_reason = 0
                    self.exporter(value)
                else:
                    remaining_inactives = False
            except TypeError:
                remaining_inactives = False

    def consume(self, pkt_info):
        """ consume a packet and update Streamer status """
        self.processed_packets += 1  # increment total processed packet counter
        key = get_flow_key(pkt_info)
        if key in self.__flows:
            flow_status = self.__flows[key].update(pkt_info, self.active_timeout, self.user_classifiers,
                                                   self.user_metrics)
            if flow_status == 1:
                self.exporter(self.__flows[key])
                flow = Flow(pkt_info, self.user_classifiers, self.user_metrics)
                self.__flows[flow.key] = flow
                self.__flows[flow.key].update(pkt_info, self.active_timeout, self.user_classifiers, self.user_metrics)
            if flow_status > 2:
                self.exporter(self.__flows[key])

        else:
            self.current_flows += 1
            flow = Flow(pkt_info, self.user_classifiers, self.user_metrics)
            flow.update(pkt_info, self.active_timeout, self.user_classifiers, self.user_metrics)
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