#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: cache.py
This file is part of nfstream.

Copyright (C) 2019-20 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from .plugin import nfstream_core_plugins, nfplugins_validator, ndpi_infos_plugins, nfstream_statistical_plugins, nDPI
from collections import OrderedDict
from .entry import NFEntry
from .ndpi import NDPI
import time as tm
import zmq


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


class NFCache(object):
    """ NFCache for entries management """
    def __init__(self, observer=None, idle_timeout=30, active_timeout=300, nroots=100,
                 core_plugins=nfstream_core_plugins, user_plugins=(),
                 dissect=True, statistics=True, max_tcp_dissections=10, max_udp_dissections=16,
                 sock_name=None, enable_guess=True):
        self.observer = observer
        self.mode = observer.mode
        try:
            self.producer = zmq.Context().socket(zmq.PUSH)
            self.producer.bind(sock_name)
        except zmq.error.ZMQError:
            raise OSError("NFStreamer failed to bind socket (producer).")
        self._roots = []  # root structure for entries caching: dict of LRUs
        self.nroots = nroots
        self.idle_timeout = idle_timeout * 1000
        self.active_timeout = active_timeout * 1000
        if self.idle_timeout < 0:
            self.idle_timeout = 0
        if self.active_timeout < 0:
            self.active_timeout = 0
        for root_idx in range(nroots):  # init root
            self._roots.append(LRU(idle_timeout=self.idle_timeout))
        self.current_tick = 0
        self.last_visited_root_idx = 0
        self.active_entries = 0
        self.idx_generator = 0
        self.processed_pkts = 0
        self.performances = [0, 0]
        self.idle_scan_period = 10
        self.idle_scan_tick = 0
        self.idle_scan_budget = 1024
        self.stopped = False
        if dissect and statistics:
            self.core_plugins = core_plugins + nfstream_statistical_plugins + ndpi_infos_plugins + \
                                [nDPI(user_data=NDPI(max_tcp_dissections=max_tcp_dissections,
                                                     max_udp_dissections=max_udp_dissections,
                                                     enable_guess=enable_guess),
                                      volatile=True)]
        elif dissect:
            self.core_plugins = core_plugins + ndpi_infos_plugins + \
                                [nDPI(user_data=NDPI(max_tcp_dissections=max_tcp_dissections,
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

    def idle_scan(self):
        remaining = True
        scanned = 0
        while remaining and scanned < self.idle_scan_budget:
            try:
                idle_idx, idle_item = self._roots[self.last_visited_root_idx].get_idle_item(self.current_tick,
                                                                                            self.core_plugins,
                                                                                            self.user_plugins)
                if idle_item is not None:  # idle
                    self.producer.send_pyobj(idle_item)
                    del self._roots[self.last_visited_root_idx][idle_idx]
                    self.active_entries -= 1  # remove it
                    scanned += 1
                else:
                    remaining = False  # no idle entries to poll
            except StopIteration:
                remaining = False  # root is empty
        self.last_visited_root_idx += 1  # we move to next root
        if self.last_visited_root_idx == self.nroots:
            self.last_visited_root_idx = 0  # back to zero check

    def terminate(self):
        """ terminate all entries in NFCache """
        for root_idx in range(self.nroots):
            for h in list(self._roots[root_idx].keys()):
                f = self._roots[root_idx][h].clean(self.core_plugins, self.user_plugins)
                self.producer.send_pyobj(f)
                self.active_entries -= 1
                del self._roots[root_idx][h]
        for plugin in self.core_plugins:
            plugin.cleanup()
        for plugin in self.user_plugins:
            plugin.cleanup()
        self.observer.close()  # close generator
        self.producer.send_pyobj(None)

    def consume(self, obs):
        """ consume an observable and produce entry """
        # classical create/update
        try:  # update entry
            entry = self._roots[obs.root_idx][obs.nfhash].update(obs,
                                                                 self.core_plugins,
                                                                 self.user_plugins,
                                                                 self.active_timeout)
            if entry is not None:
                if entry.expiration_id < 0:  # custom expiration
                    self.producer.send_pyobj(entry)
                    del self._roots[obs.root_idx][obs.nfhash]
                    self.active_entries -= 1
                else:  # active expiration
                    self.producer.send_pyobj(entry)
                    del self._roots[obs.root_idx][obs.nfhash]
                    self._roots[obs.root_idx][obs.nfhash] = NFEntry(obs,
                                                                    self.core_plugins,
                                                                    self.user_plugins,
                                                                    self.idx_generator)
                    self.idx_generator += 1
        except KeyError:  # create entry
            self._roots[obs.root_idx][obs.nfhash] = NFEntry(obs,
                                                            self.core_plugins,
                                                            self.user_plugins,
                                                            self.idx_generator)
            self.active_entries += 1
            self.idx_generator += 1

    def run(self):
        """ run NFCache main processing loop """
        for observable in self.observer:
            if not self.stopped:
                if observable is not None:
                    go_scan = False
                    if observable.time - self.idle_scan_tick >= self.idle_scan_period:
                        go_scan = True
                        self.idle_scan_tick = observable.time
                    if observable.time >= self.current_tick:
                        self.current_tick = observable.time
                    self.consume(observable)
                    if go_scan:
                        self.idle_scan()  # perform a micro scan
                else:
                    if self.mode == 1:  # live capture
                        now = int(tm.time() * 1000)
                        if now > self.current_tick:
                            self.current_tick = now
                        if now - self.idle_scan_tick >= self.idle_scan_period:
                            self.idle_scan()
                            self.idle_scan_tick = now
            else:
                break
        self.terminate()