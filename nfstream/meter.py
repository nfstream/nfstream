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
    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.move_to_end(key)  # now this item is the most recently updated

    def __eq__(self, other):
        return super().__eq__(other)

    def peak_lru_item(self):
        return next(iter(self))


class NFMeter(Process):
    """ NFMeter for entries management """
    def __init__(self, observer, idle_timeout, active_timeout, user_plugins, dissect, statistics,
                 max_tcp_dissections, max_udp_dissections, enable_guess, channel):
        super().__init__()
        self.observer = observer
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
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

    def idle_scan(self, meter_tick, cache):
        remaining = True
        scanned = 0
        while remaining and scanned < 1024:  # idle scan budget
            try:
                lru_idx = cache.peak_lru_item()
                lru_item = cache[lru_idx]
                if (meter_tick - self.idle_timeout) >= lru_item.bidirectional_last_seen_ms:  # idle
                    self.channel.put(lru_item.clean(self.core_plugins, self.user_plugins))
                    del cache[lru_idx]
                    scanned += 1
                else:
                    remaining = False  # no idle entries to poll
            except StopIteration:
                remaining = False  # root is empty

    def cleanup(self, cache):
        """ cleanup all entries in NFCache """
        for h in list(cache.keys()):
            f = cache[h].clean(self.core_plugins, self.user_plugins)
            self.channel.put(f)
            del cache[h]
        for plugin in self.core_plugins:
            plugin.cleanup()
        for plugin in self.user_plugins:
            plugin.cleanup()
        self.channel.put(None)

    def consume(self, observable, cache):
        """ consume an observable and produce entry """
        # classical create/update
        try:  # update entry
            entry = cache[observable.nfhash].update(observable,
                                                    self.core_plugins,
                                                    self.user_plugins,
                                                    self.active_timeout,
                                                    self.idle_timeout)
            if entry is not None:
                if entry.expiration_id < 0:  # custom expiration
                    self.channel.put(entry)
                    del cache[observable.nfhash]
                else:  # active expiration
                    self.channel.put(entry)
                    del cache[observable.nfhash]
                    cache[observable.nfhash] = NFEntry(observable, self.core_plugins, self.user_plugins)
        except KeyError:  # create entry
            cache[observable.nfhash] = NFEntry(observable, self.core_plugins, self.user_plugins)

    def run(self):
        """ run NFMeter main processing loop """
        meter_tick = 0
        idle_scan_tick = 0
        idle_scan_interval = 10
        cache = NFCache()
        observer = self.observer
        try:
            for observable_type, time, observable in observer:
                if observable_type == 1:
                    go_scan = False
                    if time - idle_scan_tick >= idle_scan_interval:
                        go_scan = True
                        idle_scan_tick = time
                    if time >= meter_tick:
                        meter_tick = time
                    self.consume(observable, cache)
                    if go_scan:
                        self.idle_scan(meter_tick, cache)  # perform a micro scan
                else:
                    if time > meter_tick:
                        meter_tick = time
                    if time - idle_scan_tick >= idle_scan_interval:
                        self.idle_scan(meter_tick, cache)
                        idle_scan_tick = time
            raise KeyboardInterrupt
        except KeyboardInterrupt:
            del observer
            self.observer.close()
            self.cleanup(cache)
