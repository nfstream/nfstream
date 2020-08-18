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
multiprocessing.set_start_method("fork")
from .observer import NFObserver
from siphash import siphash_64
from .cache import NFCache
import psutil
import pandas as pd
import time as tm
import secrets
import zmq
import sys
import os


def nf_receive_flow(channel):
    while True:
        try:
            flow = channel.recv_pyobj(flags=zmq.NOBLOCK)
            return flow
        except zmq.Again:
            pass


class NFStreamer(object):
    streamer_id = 0  # class id generator
    """ Network Flow Streamer """
    def __init__(self, source=None, decode_tunnels=True, bpf_filter=None, promisc=True, snaplen=65535,
                 idle_timeout=30, active_timeout=300, plugins=(),
                 dissect=True, statistics=False, max_tcp_dissections=80, max_udp_dissections=16, enable_guess=True,
                 njobs=-1
                 ):
        NFStreamer.streamer_id += 1
        self._source = source
        now = str(tm.time())
        if njobs <= 0:
            self.n_caches = psutil.cpu_count(logical=False) - 1
        elif njobs == 1:
            self.n_caches = 1
        else:
            if njobs <= psutil.cpu_count(logical=False):
                self.n_caches = njobs - 1
            else:
                self.n_caches = psutil.cpu_count(logical=False) - 1
        if self.n_caches == 0:
            self.n_caches = 1
        print("Running {} parallel caching jobs.".format(self.n_caches))
        self.caches = []
        self.n_terminated = 0
        self._sock_name = "ipc:///tmp/nfstream-{pid}-{streamerid}-{ts}".format(pid=os.getpid(),
                                                                               streamerid=NFStreamer.streamer_id,
                                                                               ts=now)
        try:
            for i in range(self.n_caches):
                self.caches.append(NFCache(observer=NFObserver(source=source, snaplen=snaplen,
                                                               decode_tunnels=decode_tunnels,
                                                               bpf_filter=bpf_filter,
                                                               promisc=promisc,
                                                               nroots=self.n_caches,
                                                               root_idx=i
                                                               ),
                                           idle_timeout=idle_timeout,
                                           active_timeout=active_timeout,
                                           user_plugins=plugins,
                                           dissect=dissect,
                                           statistics=statistics,
                                           max_tcp_dissections=max_tcp_dissections,
                                           max_udp_dissections=max_udp_dissections,
                                           sock_name=self._sock_name,
                                           enable_guess=enable_guess))
                self.caches[i].daemon = True  # demonize cache

        except OSError as ose:
            sys.exit(ose)
        except ValueError as ve:
            sys.exit(ve)
        except TypeError as te:
            sys.exit(te)
        self._stopped = False

    def __iter__(self):
        self.ctx = zmq.Context()
        self._consumer = self.ctx.socket(zmq.PULL)
        self._consumer.bind(self._sock_name)
        try:
            for i in range(self.n_caches):
                self.caches[i].start()
            while True:
                try:
                    flow = nf_receive_flow(self._consumer)
                    if flow is None:
                        self.n_terminated += 1
                        if self.n_terminated == self.n_caches:
                            break
                    else:
                        yield flow
                except KeyboardInterrupt:
                    if not self._stopped:
                        self._stopped = True
            for i in range(self.n_caches):
                self.caches[i].join()
            self._consumer.close()
            self.ctx.destroy()
        except RuntimeError:
            return None

    def to_csv(self, sep="|", path=None, ip_anonymization=False):
        if path is None:
            output_path = str(self._source) + '.csv'
        else:
            output_path = path
        if os.path.exists(output_path):
            sys.exit("Output file exists: {}. Please specify a valid file path.".format(output_path))
        else:
            total_flows = 0
            crypto_key = secrets.token_bytes(16)
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
                            values[src_ip_index] = int.from_bytes(siphash_64(crypto_key, values[src_ip_index].encode()),
                                                                  sys.byteorder)
                            values[dst_ip_index] = int.from_bytes(siphash_64(crypto_key, values[dst_ip_index].encode()),
                                                                  sys.byteorder)
                        to_export = sep.join([str(i) for i in values]) + "\n"
                        f.write(to_export.encode('utf-8'))
                        total_flows = total_flows + 1
                    except KeyboardInterrupt:
                        if not self._stopped:
                            self._stopped = True
                return total_flows

    def to_pandas(self, ip_anonymization=False):
        """ streamer to pandas function """
        temp_file_path = self._sock_name.replace("ipc:///tmp/", "") + ".csv"
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



