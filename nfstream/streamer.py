#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
streamer.py
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

import multiprocessing
import pandas as pd
import time as tm
import secrets
import os
import datetime
from collections.abc import Iterable
from collections import namedtuple
from psutil import net_if_addrs, cpu_count
from hashlib import blake2b
from os.path import isfile
from .meter import NFMeter
from.plugin import NFPlugin
# Set fork as method to avoid issues on macos with spawn default value
multiprocessing.set_start_method("fork")


observer_cfg = namedtuple('ObserverConfiguration', ['source',
                                                    'snaplen',
                                                    'decode_tunnels',
                                                    'bpf_filter',
                                                    'promisc',
                                                    'n_roots',
                                                    'root_idx',
                                                    'mode'])

meter_cfg = namedtuple('MeterConfiguration', ['idle_timeout',
                                              'active_timeout',
                                              'accounting_mode',
                                              'udps',
                                              'n_dissections',
                                              'statistics',
                                              'splt'])


def csv_converter(values):
    """ convert non numeric values to using their __str__ method and ensure quoting """
    for idx in range(len(values)):
        if not isinstance(values[idx], float) and not isinstance(values[idx], int):
            values[idx] = str(values[idx])
            values[idx] = values[idx].replace('\"', '\\"')
            values[idx] = "\"" + values[idx] + "\""


def open_file(path, chunked, chunk_idx):
    if not chunked:
        return open(path, 'wb')
    else:
        return open(path.replace("csv", "{}.csv".format(chunk_idx)), 'wb')


class NFStreamer(object):
    streamer_id = 0  # class id generator
    """ Network Flow Streamer """
    def __init__(self,
                 source=None,
                 decode_tunnels=True,
                 bpf_filter=None,
                 promiscuous_mode=True,
                 snapshot_length=1536,
                 idle_timeout=30,
                 active_timeout=300,
                 accounting_mode=0,
                 udps=None,
                 n_dissections=20,
                 statistical_analysis=False,
                 splt_analysis=0,
                 n_meters=0,
                 performance_summary=False,
                 ):
        NFStreamer.streamer_id += 1
        self.mode = 0
        self.source = source
        self.decode_tunnels = decode_tunnels
        self.bpf_filter = bpf_filter
        self.promiscuous_mode = promiscuous_mode
        self.snapshot_length = snapshot_length
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.accounting_mode = accounting_mode
        self.udps = udps
        self.n_dissections = n_dissections
        self.statistical_analysis = statistical_analysis
        self.splt_analysis = splt_analysis
        self.n_meters = n_meters
        self.performance_summary = performance_summary

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        if not isinstance(value, str):
            raise ValueError("Please specify a pcap file path or a valid network interface name as source.")
        else:
            available_interfaces = net_if_addrs().keys()
            if value in available_interfaces:
                self.mode = 1
            elif ".pcap" in value[-5:] and isfile(value):
                self.mode = 0
            else:
                raise ValueError("Please specify a pcap file path or a valid network interface name as source.")
        self._source = value

    @property
    def decode_tunnels(self):
        return self._decode_tunnels

    @decode_tunnels.setter
    def decode_tunnels(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid decode_tunnels parameter (possible values: True, False).")
        self._decode_tunnels = value

    @property
    def bpf_filter(self):
        return self._bpf_filter

    @bpf_filter.setter
    def bpf_filter(self, value):
        if not isinstance(value, str) and value is not None:
            raise ValueError("Please specify a valid bpf_filter format.")
        self._bpf_filter = value

    @property
    def promiscuous_mode(self):
        return self._promiscuous_mode

    @promiscuous_mode.setter
    def promiscuous_mode(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid promiscuous_mode parameter (possible values: True, False).")
        self._promiscuous_mode = value

    @property
    def snapshot_length(self):
        return self._snapshot_length

    @snapshot_length.setter
    def snapshot_length(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and value <= 0):
            raise ValueError("Please specify a valid snapshot_length parameter (positive integer).")
        self._snapshot_length = value

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and
                                          ((value < 0) or (value*1000) > 18446744073709551615)):  # max uint64_t
            raise ValueError("Please specify a valid idle_timeout parameter (positive integer in seconds).")
        self._idle_timeout = value

    @property
    def active_timeout(self):
        return self._active_timeout

    @active_timeout.setter
    def active_timeout(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and
                                          ((value < 0) or (value*1000) > 18446744073709551615)):  # max uint64_t
            raise ValueError("Please specify a valid active_timeout parameter (positive integer in seconds).")
        self._active_timeout = value

    @property
    def accounting_mode(self):
        return self._accounting_mode

    @accounting_mode.setter
    def accounting_mode(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and value not in [0, 1, 2, 3]):
            raise ValueError("Please specify a valid accounting_mode parameter (possible values: 0, 1, 2, 3).")
        self._accounting_mode = value

    @property
    def udps(self):
        return self._udps

    @udps.setter
    def udps(self, value):
        multiple = isinstance(value, Iterable)
        if multiple:
            for plugin in value:
                if isinstance(plugin, NFPlugin):
                    pass
                else:
                    raise ValueError("User defined plugins must inherit from NFPlugin type.")
            self._udps = value
        else:
            if isinstance(value, NFPlugin):
                self._udps = (value,)
            else:
                if value is None:
                    self._udps = ()
                else:
                    raise ValueError("User defined plugins must inherit from NFPlugin type.")

    @property
    def n_dissections(self):
        return self._n_dissections

    @n_dissections.setter
    def n_dissections(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and (value < 0 or value > 255)):
            raise ValueError("Please specify a valid n_dissections parameter (possible values in : [0,...,255]).")
        self._n_dissections = value

    @property
    def statistical_analysis(self):
        return self._statistical_analysis

    @statistical_analysis.setter
    def statistical_analysis(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid statistical_analysis parameter (possible values: True, False).")
        self._statistical_analysis = value

    @property
    def splt_analysis(self):
        return self._splt_analysis

    @splt_analysis.setter
    def splt_analysis(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and (value < 0 or value > 255)):
            raise ValueError("Please specify a valid splt_analysis parameter (possible values in : [0,...,255])")
        self._splt_analysis = value

    @property
    def n_meters(self):
        return self._n_meters

    @n_meters.setter
    def n_meters(self, value):
        if isinstance(value, int) and value >= 0:
            pass
        else:
            raise ValueError("Please specify a valid n_meters parameter (>=1 or 0 for auto scaling).")
        n_cores = cpu_count(logical=False)
        if value == 0:
            self._n_meters = n_cores - 1
        else:
            if (value + 1) <= n_cores:
                self._n_meters = value
            else:  # avoid contention
                print("WARNING: NFStreamer set with n_meters:{}.\n"
                      "         Such configuration runs {} processes > {} physical cores on this host.\n"
                      "         This will results in contention and performances degradation.".format(value,
                                                                                                      value + 1,
                                                                                                      n_cores))
                self._n_meters = value

    @property
    def performance_summary(self):
        return self._performance_summary

    @performance_summary.setter
    def performance_summary(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid performance_summary parameter (possible values: True, False).")
        self._performance_summary = value

    def __iter__(self):
        start_time = datetime.datetime.now()
        meters = []
        meters_load = {}
        processed_packets = 0
        discarded_packets = 0
        dropped_packets = 0
        dropped_intf_packets = 0
        n_terminated = 0
        channel = multiprocessing.Queue(maxsize=32767)  # Backpressure strategy.
        # We set it to (2^15-1) to cope with OSX maximum semaphore value.
        n_meters = self.n_meters
        if n_meters == 0:
            n_meters = 1
        try:
            for i in range(n_meters):
                meters_load[i] = 0
                meters.append(NFMeter(observer_cfg=observer_cfg(source=self.source,
                                                                snaplen=self.snapshot_length,
                                                                decode_tunnels=self.decode_tunnels,
                                                                bpf_filter=self.bpf_filter,
                                                                promisc=self.promiscuous_mode,
                                                                n_roots=n_meters,
                                                                root_idx=i,
                                                                mode=self.mode),
                                      meter_cfg=meter_cfg(idle_timeout=self.idle_timeout*1000,
                                                          active_timeout=self.active_timeout*1000,
                                                          accounting_mode=self.accounting_mode,
                                                          udps=self.udps,
                                                          n_dissections=self.n_dissections,
                                                          statistics=self.statistical_analysis,
                                                          splt=self.splt_analysis),
                                      channel=channel))
                meters[i].daemon = True  # demonize meter
                meters[i].start()
            idx_generator = 0
            while True:
                try:
                    recv = channel.get()
                    if isinstance(recv, list):  # termination and stats
                        n_terminated += 1
                        meters_load[recv[0]] = recv[1]
                        processed_packets += recv[1]
                        discarded_packets = max(discarded_packets, recv[2])
                        dropped_packets = max(dropped_packets, recv[3])
                        dropped_intf_packets = max(dropped_intf_packets, recv[4])
                        if n_terminated == n_meters:
                            if self.performance_summary:
                                for i in range(n_meters):
                                    if processed_packets != 0:
                                        meters_load[i] = round((meters_load[i]/processed_packets)*100, 2)
                                print("\nNFStreamer performance summary:")
                                print("- Processing time                   : {}".format(
                                    datetime.datetime.now()-start_time)
                                )
                                print("- Metering load dispatch (%)        : {}".format(meters_load))
                                print("- Processed flows                   : {}".format(idx_generator))
                                print("- Processed packets                 : {}".format(processed_packets))
                                print("- Discarded packets (e.g. nonIP)    : {}".format(discarded_packets))
                                if self.mode:
                                    print("- Filtered/Dropped packets (kernel) : {}".format(dropped_packets))
                                    print("- Dropped packets (interface)       : {}".format(dropped_intf_packets))
                                    print("Please read: https://github.com/nfstream/nfstream/blob/master/assets/NOTE.md")
                            break  # We finish up when all metering jobs are terminated
                    else:
                        recv.id = idx_generator  # Unify ID
                        idx_generator += 1
                        yield recv
                except KeyboardInterrupt:
                    pass  # We pass as we wait for metering jobs (they will handle the keyboard interupt)
            for i in range(n_meters):
                meters[i].join()  # Join metring jobs
            channel.close()  # We close the queue
            channel.join_thread()  # and we join its thread
        except ValueError as observer_error: # job initiation failed due to some bad observer parameters.
            raise ValueError(observer_error)

    def to_csv(self, path=None, ip_anonymization=False, flows_per_file=0):
        if not isinstance(flows_per_file, int) or isinstance(flows_per_file, int) and flows_per_file < 0:
            raise ValueError("Please specify a valid flows_per_file parameter (>= 0).")
        chunked = True
        chunk_idx = -1
        if flows_per_file == 0:
            chunked = False
        if path is None:
            output_path = str(self.source) + '.csv'
        else:
            output_path = path
        total_flows = 0
        chunk_flows = 0
        # We generate a random secret key
        crypto_key = secrets.token_bytes(64)
        f = None
        for flow in self:
            try:
                if total_flows == 0 or (chunked and (chunk_flows > flows_per_file)):  # header creation
                    if f is not None:
                        f.close()
                    chunk_flows = 1
                    chunk_idx += 1
                    f = open_file(output_path, chunked, chunk_idx)
                    header = ','.join([str(i) for i in flow.keys()]) + "\n"
                    src_ip_index = flow.keys().index("src_ip")
                    dst_ip_index = flow.keys().index("dst_ip")
                    f.write(header.encode('utf-8'))
                values = flow.values()
                if ip_anonymization:
                    # Anonymization use generated secret key to hash using blake2B algo src and dst IPs.
                    values[src_ip_index] = blake2b(values[src_ip_index].encode(),
                                                    digest_size=64,
                                                    key=crypto_key).hexdigest()
                    values[dst_ip_index] = blake2b(values[dst_ip_index].encode(),
                                                   digest_size=64,
                                                   key=crypto_key).hexdigest()
                csv_converter(values)
                to_export = ','.join([str(i) for i in values]) + "\n"
                f.write(to_export.encode('utf-8'))
                total_flows = total_flows + 1
                chunk_flows += 1
            except KeyboardInterrupt:
                pass
        if not f.closed:
            f.close()
        return total_flows

    def to_pandas(self, ip_anonymization=False):
        """ streamer to pandas function """
        temp_file_path = "nfstream-{pid}-{iid}-{ts}?csv".format(pid=os.getpid(),
                                                                iid=NFStreamer.streamer_id,
                                                                ts=tm.time())
        total_flows = self.to_csv(path=temp_file_path, ip_anonymization=ip_anonymization, flows_per_file=0)
        if total_flows >= 0:
            df = pd.read_csv(temp_file_path)
            if total_flows != df.shape[0]:
                print("WARNING: {} flows ignored by pandas type conversion. Consider using to_csv() "
                      "method if drops are critical.".format(abs(df.shape[0] - total_flows)))
        else:
            df = None
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return df
