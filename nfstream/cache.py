#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
cache.py
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

from .plugin import nfstream_core_plugins, nfplugins_validator, ndpi_infos_plugins, nfstream_statistical_plugins, nDPI
from collections import OrderedDict
from .entry import NFEntry
from .ndpi import NDPI
from multiprocessing import Process
import time as tm
import zmq


def nf_send_flow(channel, flow):
    sent = False
    while not sent:
        try:
            channel.send_pyobj(flow, flags=zmq.NOBLOCK)
            sent = True
        except zmq.Again:
            sent = False


class LRU(OrderedDict):
    """ Thread safe least recently updated dict """
    def __init__(self, idle_timeout, *args, **kwds):
        super().__init__(*args, **kwds)
        self._idle_timeout = idle_timeout

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.move_to_end(key)  # now this item is the most recently updated

    def __eq__(self, other):
        return super().__eq__(o)

    def get_idle_item(self, current_tick, core, user):
        nxt = next(iter(self))
        return nxt, self[nxt].idle(self._idle_timeout, current_tick, core, user)


class NFCache(Process):
    """ NFCache for entries management """
    def __init__(self, observer=None, idle_timeout=30, active_timeout=300,
                 core_plugins=nfstream_core_plugins, user_plugins=(),
                 dissect=True, statistics=True, max_tcp_dissections=10, max_udp_dissections=16,
                 sock_name=None, enable_guess=True):
        super().__init__()
        self.observer = observer
        self.mode = observer.mode
        self.idle_timeout = idle_timeout * 1000
        self.active_timeout = active_timeout * 1000
        if self.idle_timeout < 0:
            self.idle_timeout = 0
        if self.active_timeout < 0:
            self.active_timeout = 0
        self._roots = LRU(idle_timeout=self.idle_timeout)
        self.current_tick = 0
        self.active_entries = 0
        self.idx_generator = 0
        self.processed_pkts = 0
        self.performances = [0, 0]
        self.idle_scan_period = 10
        self.idle_scan_tick = 0
        self.idle_scan_budget = 1024
        self.sock_name = sock_name
        if dissect and statistics:
            self.core_plugins = core_plugins + nfstream_statistical_plugins + ndpi_infos_plugins + \
                                [nDPI(ndpi=NDPI(max_tcp_dissections=max_tcp_dissections,
                                                max_udp_dissections=max_udp_dissections,
                                                enable_guess=enable_guess),
                                      volatile=True)]
        elif dissect:
            self.core_plugins = core_plugins + ndpi_infos_plugins + \
                                [nDPI(ndpi=NDPI(max_tcp_dissections=max_tcp_dissections,
                                                max_udp_dissections=max_udp_dissections,
                                                enable_guess=enable_guess),
                                      volatile=True)]
        elif statistics:
            self.core_plugins = core_plugins + nfstream_statistical_plugins
        else:
            self.core_plugins = core_plugins

        try:
            nfplugins_validator(user_plugins)
        except TypeError:
            raise TypeError("Streamer initiated with unknown type plugins (must be NFPlugin type).")
        except ValueError:
            raise TypeError("Streamer initiated with non unique plugins names. Consider renaming your added plugins.")
        self.user_plugins = user_plugins

    def idle_scan(self, producer):
        remaining = True
        scanned = 0
        while remaining and scanned < self.idle_scan_budget:
            try:
                idle_idx, idle_item = self._roots.get_idle_item(self.current_tick,
                                                                                            self.core_plugins,
                                                                                            self.user_plugins)
                if idle_item is not None:  # idle
                    nf_send_flow(producer, idle_item)
                    del self._roots[idle_idx]
                    self.active_entries -= 1  # remove it
                    scanned += 1
                else:
                    remaining = False  # no idle entries to poll
            except StopIteration:
                remaining = False  # root is empty

    def finish(self, producer, context):
        """ finish all entries in NFCache """
        for h in list(self._roots.keys()):
            f = self._roots[h].clean(self.core_plugins, self.user_plugins)
            nf_send_flow(producer, f)
            self.active_entries -= 1
            del self._roots[h]
        for plugin in self.core_plugins:
            plugin.cleanup()
        for plugin in self.user_plugins:
            plugin.cleanup()
        self.observer.close()  # close generator
        nf_send_flow(producer, None)
        producer.close()
        context.destroy()

    def consume(self, obs, producer):
        """ consume an observable and produce entry """
        # classical create/update
        try:  # update entry
            entry = self._roots[obs.nfhash].update(obs,
                                                                 self.core_plugins,
                                                                 self.user_plugins,
                                                                 self.active_timeout)
            if entry is not None:
                if entry.expiration_id < 0:  # custom expiration
                    nf_send_flow(producer, entry)
                    del self._roots[obs.nfhash]
                    self.active_entries -= 1
                else:  # active expiration
                    nf_send_flow(producer, entry)
                    del self._roots[obs.nfhash]
                    self._roots[obs.nfhash] = NFEntry(obs,
                                                                    self.core_plugins,
                                                                    self.user_plugins,
                                                                    self.idx_generator)
                    self.idx_generator += 1
        except KeyError:  # create entry
            self._roots[obs.nfhash] = NFEntry(obs,
                                                            self.core_plugins,
                                                            self.user_plugins,
                                                            self.idx_generator)
            self.active_entries += 1
            self.idx_generator += 1

    def run(self):
        """ run NFCache main processing loop """
        try:
            ctx = zmq.Context()
            producer = ctx.socket(zmq.PUSH)
            producer.connect(self.sock_name)
        except zmq.error.ZMQError:
            raise OSError("NFStreamer failed to bind socket (producer).")
        try:
            for observable in self.observer:
                if observable is not None:
                    go_scan = False
                    if observable.time - self.idle_scan_tick >= self.idle_scan_period:
                        go_scan = True
                        self.idle_scan_tick = observable.time
                    if observable.time >= self.current_tick:
                        self.current_tick = observable.time
                    self.consume(observable, producer)
                    if go_scan:
                        self.idle_scan(producer)  # perform a micro scan
                else:
                    if self.mode == 1:  # live capture
                        now = int(tm.time() * 1000)
                        if now > self.current_tick:
                            self.current_tick = now
                        if now - self.idle_scan_tick >= self.idle_scan_period:
                            self.idle_scan(producer)
                            self.idle_scan_tick = now
            self.finish(producer, ctx)
        except KeyboardInterrupt:
            self.finish(producer, ctx)