#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lru import LRU  # for LRU streamer management
from .observer import Observer
from .classifier import NDPIClassifier, NFStreamClassifier
import ipaddress
import sys


def emergency_callback(key, value):
    """ Callback used for Streamer eviction method """
    if 'ndpi' in list(value.classifiers.keys()):
        value.ndpi_flow = None
    print("WARNING: Streamer capacity limit reached: lru flow entry dropped.")


class Flow:
    """ Flow entry structure """
    def __init__(self, pkt_info, streamer_classifiers, streamer_metrics):
        self.start_time = pkt_info.timestamp
        self.end_time = pkt_info.timestamp
        self.export_reason = -1
        self.key = pkt_info.hash
        self.ip_src_int = pkt_info.ip_src_int
        self.ip_dst_int = pkt_info.ip_dst_int
        if pkt_info.version == 4:
            self.ip_src_str = str(ipaddress.IPv4Address(self.ip_src_int)).replace(':0:', '::')
            self.ip_dst_str = str(ipaddress.IPv4Address(self.ip_dst_int)).replace(':0:', '::')
        else:
            self.ip_src_str = str(ipaddress.IPv6Address(self.ip_src_int)).replace(':0:', '::')
            self.ip_dst_str = str(ipaddress.IPv6Address(self.ip_dst_int)).replace(':0:', '::')
        self.src_port = pkt_info.src_port
        self.dst_port = pkt_info.dst_port
        self.ip_protocol = pkt_info.ip_protocol
        self.vlan_id = pkt_info.vlan_id
        self.version = pkt_info.version
        self.src_to_dst_pkts = 0
        self.dst_to_src_pkts = 0
        self.src_to_dst_bytes = 0
        self.dst_to_src_bytes = 0
        self.syn_count = [0, 0]
        self.cwr_count = [0, 0]
        self.ece_count = [0, 0]
        self.urg_count = [0, 0]
        self.ack_count = [0, 0]
        self.psh_count = [0, 0]
        self.rst_count = [0, 0]
        self.fin_count = [0, 0]
        self.metrics = {}
        self.classifiers = {}
        for metric_name in list(streamer_metrics.keys()):
            self.metrics[metric_name] = 0
        for name, classifier in streamer_classifiers.items():
            self.classifiers[classifier.name] = {}
            classifier.on_flow_init(self)

    def update(self, pkt_info, active_timeout, streamer_classifiers, streamer_metrics):
        """ Update a flow from a packet and return status """
        if (pkt_info.timestamp - self.end_time) >= (active_timeout*1000):  # Active Expiration
            return 1, self
        else:  # We start by core management
            self.end_time = pkt_info.timestamp
            if (self.ip_src_int == pkt_info.ip_src_int and self.ip_dst_int == pkt_info.ip_dst_int and
                    self.src_port == pkt_info.src_port and self.dst_port == pkt_info.dst_port
                    and self.ip_protocol == pkt_info.ip_protocol):
                self.src_to_dst_pkts += 1
                self.src_to_dst_bytes += pkt_info.length
                direction = 0
            else:
                self.dst_to_src_pkts += 1
                self.dst_to_src_bytes += pkt_info.length
                direction = 1

            self.syn_count[direction] += pkt_info.syn
            self.cwr_count[direction] += pkt_info.cwr
            self.ece_count[direction] += pkt_info.ece
            self.urg_count[direction] += pkt_info.urg
            self.ack_count[direction] += pkt_info.ack
            self.psh_count[direction] += pkt_info.psh
            self.rst_count[direction] += pkt_info.rst
            self.fin_count[direction] += pkt_info.fin

            for name, classifier in streamer_classifiers.items():
                classifier.on_flow_update(pkt_info, self, direction)

            metrics_names = list(streamer_metrics.keys())
            for metric_name in metrics_names:
                self.metrics[metric_name] = streamer_metrics[metric_name](pkt_info, self, direction)

            return self.export_reason, self

    def __str__(self):
        metrics = {'ip_src': self.ip_src_str,
                   'src_port': self.src_port,
                   'ip_dst': self.ip_dst_str,
                   'dst_port': self.dst_port,
                   'ip_protocol': self.ip_protocol,
                   'src_to_dst_pkts': self.src_to_dst_pkts,
                   'dst_to_src_pkts': self.dst_to_src_pkts,
                   'src_to_dst_bytes': self.src_to_dst_bytes,
                   'dst_to_src_bytes': self.dst_to_src_bytes,
                   'syn_count': self.syn_count,
                   'cwr_count': self.cwr_count,
                   'ece_count': self.ece_count,
                   'urg_count': self.urg_count,
                   'ack_count': self.ack_count,
                   'psh_count': self.psh_count,
                   'rst_count': self.rst_count,
                   'fin_count': self.fin_count,
                   'start_time': self.start_time,
                   'end_time': self.end_time,
                   'export_reason': self.export_reason,
                   'metrics': self.metrics
                   }
        return str(metrics)


class Streamer:
    """ streamer for flows management """
    num_streamers = 0

    def __init__(self, source=None, capacity=128000, active_timeout=120, inactive_timeout=60,
                 user_metrics=None, user_classifiers=None, enable_ndpi=True, bpf_filter=None, snaplen=65535):
        Streamer.num_streamers += 1
        try:
            self.__pkt_info_gen = Observer(source=source, filter_str=bpf_filter, snaplen=snaplen)
        except OSError as e:
            sys.exit(e)
        self.__exports = []
        self.__flows = LRU(capacity, callback=emergency_callback)  # LRU cache
        self._capacity = self.__flows.get_size()  # Streamer capacity (default: 128000)
        self.active_timeout = active_timeout  # expiration active timeout
        self.inactive_timeout = inactive_timeout * 1000  # expiration inactive timeout
        if self.inactive_timeout < 1000:
            self.scan_period = 0
        else:
            self.scan_period = 1000
        self.current_flows = 0  # counter for stored flows
        self.current_tick = 0  # current timestamp
        self.last_inactive_watch_tick = 0
        self.processed_packets = 0  # current timestamp
        self.user_classifiers = {}
        if user_classifiers is not None:
            try:
                classifier_iterator = iter(user_classifiers)
                for classifier in classifier_iterator:
                    if isinstance(classifier, NFStreamClassifier):
                        self.user_classifiers[classifier.name] = classifier
                    else:
                        raise ValueError
            except ValueError:
                sys.exit("User Classifier type must be NFStreamClassifier.")
            except TypeError:
                if isinstance(user_classifiers, NFStreamClassifier):
                    self.user_classifiers[user_classifiers.name] = user_classifiers
                else:
                    sys.exit("User Classifier type must be NFStreamClassifier.")
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

        self.__pkt_info_gen.packet_generator.close()

    def exporter(self, flow):
        """ export method for a flow trigger_type:0(inactive), 1(active), 2(flush) """
        for classifier_name, classifier in self.user_classifiers.items():
            self.user_classifiers[classifier_name].on_flow_terminate(flow)
        del self.__flows[flow.key]
        self.current_flows -= 1
        self.__exports.append(flow)

    def inactive_watcher(self):
        """ inactive expiration management """
        if self.current_tick - self.last_inactive_watch_tick >= self.scan_period:
            remaining_inactives = True
            while remaining_inactives:
                try:
                    key, value = self.__flows.peek_last_item()
                    if (self.current_tick - value.end_time) >= self.inactive_timeout:
                        value.export_reason = 0
                        self.exporter(value)
                    else:
                        remaining_inactives = False
                except TypeError:
                    remaining_inactives = False
            self.last_inactive_watch_tick = self.current_tick
        else:
            return

    def consume(self, pkt_info):
        """ consume a packet and update Streamer status """
        self.processed_packets += 1  # increment total processed packet counter
        if pkt_info.timestamp > self.current_tick:
            self.current_tick = pkt_info.timestamp
        if pkt_info.hash in self.__flows:
            flow_status = self.__flows[pkt_info.hash].update(pkt_info,
                                                             self.active_timeout,
                                                             self.user_classifiers,
                                                             self.user_metrics)
            if flow_status[0] == 1:
                self.exporter(flow_status[1])
                flow = Flow(pkt_info, self.user_classifiers, self.user_metrics)
                flow.update(pkt_info,
                            self.active_timeout,
                            self.user_classifiers,
                            self.user_metrics)
                self.__flows[pkt_info.hash] = flow
            if flow_status[0] > 2:
                self.exporter(flow_status[1])

        else:
            self.current_flows += 1
            flow = Flow(pkt_info, self.user_classifiers, self.user_metrics)
            flow.update(pkt_info, self.active_timeout, self.user_classifiers, self.user_metrics)
            self.__flows[pkt_info.hash] = flow

        self.inactive_watcher()

    def __iter__(self):
        for pkt_info in self.__pkt_info_gen:
            self.consume(pkt_info)
            for export in self.__exports:
                yield export
            self.__exports = []
        self.terminate()
        for export in self.__exports:
            yield export
        self.__exports = []
