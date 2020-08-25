#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
meter.py
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

from .plugin import nfstream_core_plugins, ndpi_infos_plugins, nfstream_statistical_plugins, nDPI
from collections import OrderedDict
from .entry import NFEntry
from .ndpi import NDPI
from multiprocessing import Process


class NFCache(OrderedDict):
    """ Least recently updated dictionary """
    def __init__(self, idle_timeout, *args, **kwds):
        super().__init__(*args, **kwds)
        self._idle_timeout = idle_timeout

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.move_to_end(key)  # now this item is the most recently updated

    def __eq__(self, other):
        return super().__eq__(other)

    def get_idle_item(self, current_tick, core, user):
        nxt = next(iter(self))
        return nxt, self[nxt].idle(self._idle_timeout, current_tick, core, user)


class NFMeter(Process):
    """ NFCache for entries management """
    def __init__(self, observer, idle_timeout, active_timeout, user_plugins, dissect, statistics,
                 max_tcp_dissections, max_udp_dissections, enable_guess, channel):
        super().__init__()
        self.observer = observer
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self._roots = NFCache(idle_timeout=self.idle_timeout)
        self.current_tick = 0
        self.idle_scan_period = 10
        self.idle_scan_tick = 0
        self.idle_scan_budget = 1024
        if dissect and statistics:
            self.core_plugins = nfstream_core_plugins + nfstream_statistical_plugins + ndpi_infos_plugins + \
                                [nDPI(ndpi=NDPI(max_tcp_dissections=max_tcp_dissections,
                                                max_udp_dissections=max_udp_dissections,
                                                enable_guess=enable_guess),
                                      volatile=True)]
        elif dissect:
            self.core_plugins = nfstream_core_plugins + ndpi_infos_plugins + \
                                [nDPI(ndpi=NDPI(max_tcp_dissections=max_tcp_dissections,
                                                max_udp_dissections=max_udp_dissections,
                                                enable_guess=enable_guess),
                                      volatile=True)]
        elif statistics:
            self.core_plugins = nfstream_core_plugins + nfstream_statistical_plugins
        else:
            self.core_plugins = nfstream_core_plugins
        self.user_plugins = user_plugins
        self.channel = channel

    def idle_scan(self):
        remaining = True
        scanned = 0
        while remaining and scanned < self.idle_scan_budget:
            try:
                idle_idx, idle_item = self._roots.get_idle_item(self.current_tick, self.core_plugins, self.user_plugins)
                if idle_item is not None:  # idle
                    self.channel.put(idle_item)
                    del self._roots[idle_idx]
                    scanned += 1
                else:
                    remaining = False  # no idle entries to poll
            except StopIteration:
                remaining = False  # root is empty

    def finish(self):
        """ finish all entries in NFCache """
        for h in list(self._roots.keys()):
            f = self._roots[h].clean(self.core_plugins, self.user_plugins)
            self.channel.put(f)
            del self._roots[h]
        for plugin in self.core_plugins:
            plugin.cleanup()
        for plugin in self.user_plugins:
            plugin.cleanup()
        self.observer.close()  # close generator
        self.channel.put(None)

    def consume(self, obs):
        """ consume an observable and produce entry """
        # classical create/update
        try:  # update entry
            entry = self._roots[obs.nfhash].update(obs,
                                                   self.core_plugins,
                                                   self.user_plugins,
                                                   self.active_timeout,
                                                   self.idle_timeout)
            if entry is not None:
                if entry.expiration_id < 0:  # custom expiration
                    self.channel.put(entry)
                    del self._roots[obs.nfhash]
                else:  # active expiration
                    self.channel.put(entry)
                    del self._roots[obs.nfhash]
                    self._roots[obs.nfhash] = NFEntry(obs,
                                                      self.core_plugins,
                                                      self.user_plugins)
        except KeyError:  # create entry
            self._roots[obs.nfhash] = NFEntry(obs,
                                              self.core_plugins,
                                              self.user_plugins)

    def run(self):
        """ run NFMeter main processing loop """
        try:
            for observable_type, time, observable in self.observer:
                if observable_type == 1:
                    go_scan = False
                    if time - self.idle_scan_tick >= self.idle_scan_period:
                        go_scan = True
                        self.idle_scan_tick = time
                    if time >= self.current_tick:
                        self.current_tick = time
                    self.consume(observable)
                    if go_scan:
                        self.idle_scan()  # perform a micro scan
                else:
                    if time > self.current_tick:
                        self.current_tick = time
                    if time - self.idle_scan_tick >= self.idle_scan_period:
                        self.idle_scan()
                        self.idle_scan_tick = time
            self.finish()
        except KeyboardInterrupt:
            self.finish()
