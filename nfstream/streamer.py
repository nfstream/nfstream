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
import psutil
import sys
import os
from .observer import NFObserver
from psutil import net_if_addrs
from hashlib import blake2b
from os.path import isfile
from .meter import NFMeter
from.plugin import NFPlugin
# Set fork as method to avoid issues on macos with spawn default value
multiprocessing.set_start_method("fork")


class NFStreamer(object):
    streamer_id = 0  # class id generator
    """ Network Flow Streamer """
    def __init__(self, source=None, decode_tunnels=True, bpf_filter=None, promisc=True, snaplen=65535,
                 idle_timeout=30, active_timeout=30, plugins=(),
                 dissect=True, statistics=False, max_tcp_dissections=80, max_udp_dissections=16, enable_guess=True,
                 n_jobs=4
                 ):
        NFStreamer.streamer_id += 1
        self.source = source
        self._mode = 0
        self.decode_tunnels = decode_tunnels
        self.bpf_filter = bpf_filter
        self.promisc = promisc
        self.snaplen = snaplen
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.plugins = plugins
        self.dissect = dissect
        self.statistics = statistics
        self.max_tcp_dissections = max_tcp_dissections
        self.max_udp_dissections = max_udp_dissections
        self.enable_guess = enable_guess
        self.n_jobs = n_jobs

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        if not isinstance(value, str):
            raise ValueError("Please specify a pcap file path or a valid network interface name as source.")
        else:
            if value in net_if_addrs().keys():
                self._mode = 1
            elif ".pcap" in value[-5:] and isfile(value):
                self._mode = 0
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
    def promisc(self):
        return self._promisc

    @promisc.setter
    def promisc(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid promisc parameter (possible values: True, False).")
        self._promisc = value

    @property
    def snaplen(self):
        return self._snaplen

    @snaplen.setter
    def snaplen(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and value <= 0):
            raise ValueError("Please specify a valid snaplen parameter (positive integer).")
        self._snaplen = value

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and value < 0):
            raise ValueError("Please specify a valid idle_timeout parameter (positive integer in seconds).")
        self._idle_timeout = value

    @property
    def active_timeout(self):
        return self._active_timeout

    @active_timeout.setter
    def active_timeout(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and value < 0):
            raise ValueError("Please specify a valid active_timeout parameter (positive integer in seconds).")
        self._active_timeout = value

    @property
    def plugins(self):
        return self._plugins

    @plugins.setter
    def plugins(self, value):
        plugin_names = []
        for plugin in value:
            if isinstance(plugin, NFPlugin):
                plugin_names.append(plugin.name)
            else:
                raise ValueError("User defined plugins must inherit from NFPlugin type.")
        if len(plugin_names) != len(list(set(plugin_names))):
            raise ValueError("User defined plugins contains non unique plugins names.")
        self._plugins = value

    @property
    def dissect(self):
        return self._dissect

    @dissect.setter
    def dissect(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid dissect parameter (possible values: True, False).")
        self._dissect = value

    @property
    def statistics(self):
        return self._statistics

    @statistics.setter
    def statistics(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid statistics parameter (possible values: True, False).")
        self._statistics = value

    @property
    def max_tcp_dissections(self):
        return self._max_tcp_dissections

    @max_tcp_dissections.setter
    def max_tcp_dissections(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and value < 0):
            raise ValueError("Please specify a valid max_tcp_dissections parameter (integer >= 0).")
        self._max_tcp_dissections = value

    @property
    def max_udp_dissections(self):
        return self._max_udp_dissections

    @max_udp_dissections.setter
    def max_udp_dissections(self, value):
        if not isinstance(value, int) or (isinstance(value, int) and value < 0):
            raise ValueError("Please specify a valid max_udp_dissections parameter (integer >= 0).")
        self._max_udp_dissections = value

    @property
    def enable_guess(self):
        return self._enable_guess

    @enable_guess.setter
    def enable_guess(self, value):
        if not isinstance(value, bool):
            raise ValueError("Please specify a valid enable_guess parameter (possible values: True, False).")
        self._enable_guess = value

    @property
    def n_jobs(self):
        return self._n_jobs

    @n_jobs.setter
    def n_jobs(self, value):
        if not isinstance(value, int):
            raise ValueError("Please specify a valid n_jobs parameter (positive integer).")
        n_cores = psutil.cpu_count(logical=False)
        if value <= 0:
            self._n_jobs = n_cores
        elif value == 1:
            self._n_jobs = 1
        else:
            if value <= n_cores:
                self._n_jobs = value
            else:  # avoid contention
                self._n_jobs = n_cores

    def __iter__(self):
        meters = []
        n_terminated = 0
        channel = multiprocessing.Queue()
        n_meters = self.n_jobs - 1
        if n_meters == 0:
            n_meters = 1
        try:
            for i in range(n_meters):
                meters.append(NFMeter(observer=NFObserver(source=self.source,
                                                          snaplen=self.snaplen,
                                                          decode_tunnels=self.decode_tunnels,
                                                          bpf_filter=self.bpf_filter,
                                                          promisc=self.promisc,
                                                          n_roots=n_meters,
                                                          root_idx=i,
                                                          mode=self._mode),
                                      idle_timeout=self.idle_timeout*1000,
                                      active_timeout=self.active_timeout*1000,
                                      user_plugins=self.plugins,
                                      dissect=self.dissect,
                                      statistics=self.statistics,
                                      max_tcp_dissections=self.max_tcp_dissections,
                                      max_udp_dissections=self.max_udp_dissections,
                                      enable_guess=self.enable_guess,
                                      channel=channel))
                meters[i].daemon = True  # demonize meter
                meters[i].start()
            idx_generator = 0
            while True:
                try:
                    flow = channel.get()
                    if flow is None:
                        n_terminated += 1
                        if n_terminated == n_meters:
                            break
                    else:
                        flow.id = idx_generator
                        idx_generator += 1
                        yield flow
                except KeyboardInterrupt:
                    pass
            for i in range(n_meters):
                meters[i].join()
            channel.close()
            channel.join_thread()
        except OSError as observer_error:
            sys.exit(observer_error)

    def to_csv(self, sep="|", path=None, ip_anonymization=False):
        if path is None:
            output_path = str(self.source) + '.csv'
        else:
            output_path = path
        if os.path.exists(output_path):
            sys.exit("Output file exists: {}. Please specify a valid file path.".format(output_path))
        else:
            total_flows = 0
            crypto_key = secrets.token_bytes(64)
            with open(output_path, 'ab') as f:
                for flow in self:
                    try:
                        if total_flows == 0:  # header creation
                            header = sep.join([str(i) for i in flow.keys()]) + "\n"
                            src_ip_index = flow.keys().index("src_ip")
                            dst_ip_index = flow.keys().index("dst_ip")
                            f.write(header.encode('utf-8'))
                        values = flow.values()
                        if ip_anonymization:
                            values[src_ip_index] = blake2b(values[src_ip_index].encode(),
                                                           digest_size=64,
                                                           key=crypto_key).hexdigest()
                            values[dst_ip_index] = blake2b(values[dst_ip_index].encode(),
                                                           digest_size=64,
                                                           key=crypto_key).hexdigest()
                        to_export = sep.join([str(i) for i in values]) + "\n"
                        f.write(to_export.encode('utf-8'))
                        total_flows = total_flows + 1
                    except KeyboardInterrupt:
                        pass
                return total_flows

    def to_pandas(self, ip_anonymization=False):
        """ streamer to pandas function """
        temp_file_path = "nfs-{pid}-{iid}-{ts}.csv".format(pid=os.getpid(), iid=NFStreamer.streamer_id, ts=tm.time())
        total_flows = self.to_csv(path=temp_file_path, sep="|", ip_anonymization=ip_anonymization)
        if total_flows >= 0:
            df = pd.read_csv(temp_file_path,
                             sep="|",
                             low_memory=False,
                             skip_blank_lines=True,
                             lineterminator="\n",
                             error_bad_lines=False)
            if total_flows != df.shape[0]:
                print("WARNING: {} flows ignored by pandas type conversion. Consider using to_csv() "
                      "method if drops are critical.".format(abs(df.shape[0] - total_flows)))
        else:
            df = None
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return df
