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

from collections import OrderedDict
from multiprocessing import Process
from .observer import NFObserver
from .context import create_context
from .flow import NFlow


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

    def get_lru_key(self):
        return next(iter(self))


def meter_scan(meter_tick, cache, idle_timeout, channel, udps, sync, n_dissections, statistics, ffi, lib, dissector):
    remaining = True
    scanned = 0
    while remaining and scanned < 10000:  # idle scan budget
        try:
            flow_key = cache.get_lru_key()
            flow = cache[flow_key]
            if flow.is_idle(meter_tick, idle_timeout):  # idle
                channel.put(flow.expire(udps, sync, n_dissections, statistics, ffi, lib, dissector))
                del cache[flow_key]
                del flow
                scanned += 1
            else:
                remaining = False  # no idle entries to poll
        except StopIteration:
            remaining = False  # root is empty
    return scanned


def get_flow_key(packet, ffi):
    src_ip = ffi.string(packet.src_name).decode('utf-8', errors='ignore')
    dst_ip = ffi.string(packet.dst_name).decode('utf-8', errors='ignore')
    return packet.protocol, packet.vlan_id, \
           min(src_ip, dst_ip), max(src_ip, dst_ip),\
           min(packet.src_port, packet.dst_port), max(packet.src_port, packet.dst_port)


def consume(packet, cache, active_timeout, idle_timeout, channel, ffi, lib, udps, sync, accounting_mode, n_dissections,
            statistics, dissector):
    """ consume a packet and produce flow """
    # We maintain state for active flows computation 1 for creation, 0 for update/cut, -1 for custom expire
    flow_key = get_flow_key(packet, ffi)
    try:  # update flow
        flow = cache[flow_key].update(packet, idle_timeout, active_timeout, ffi, lib, udps, sync, accounting_mode,
                                      n_dissections, statistics, dissector)
        if flow is not None:
            if flow.expiration_id < 0:  # custom expiration
                channel.put(flow)
                del cache[flow_key]
                del flow
                state = -1
            else:  # active/inactive expiration
                channel.put(flow)
                del cache[flow_key]
                del flow
                try:
                    cache[flow_key] = NFlow(packet, ffi, lib, udps, sync, accounting_mode, n_dissections,
                                            statistics, dissector)
                except OSError:
                    print("WARNING: Failed to allocate memory space for flow creation. Flow creation aborted.")
                state = 0
        else:
            state = 0
    except KeyError:  # create flow
        try:
            if sync:
                flow = NFlow(packet, ffi, lib, udps, sync, accounting_mode, n_dissections, statistics, dissector)
                if flow.expiration_id == -1:  # A user Plugin forced expiration on the first packet
                    channel.put(flow.expire(udps, sync, n_dissections, statistics, ffi, lib, dissector))
                    del flow
                    state = 0
                else:
                    cache[flow_key] = flow
                    state = 1
            else:
                cache[flow_key] = NFlow(packet, ffi, lib, udps, sync, accounting_mode, n_dissections, statistics,
                                        dissector)
                state = 1
        except OSError:
            print("WARNING: Failed to allocate memory space for flow creation. Flow creation aborted.")
            state = 0
    return state


def meter_cleanup(cache, channel, udps, sync, n_dissections, statistics, ffi, lib, dissector):
    """ cleanup all entries in NFCache """
    for flow_key in list(cache.keys()):
        flow = cache[flow_key]
        channel.put(flow.expire(udps, sync, n_dissections, statistics, ffi, lib, dissector))
        del cache[flow_key]
        del flow
    channel.put(None)


def setup_dissector(ffi, lib, n_dissections):
    if n_dissections:
        checker = ffi.new("struct dissector_checker *")
        checker.flow_size = ffi.sizeof("struct ndpi_flow_struct")
        checker.id_size = ffi.sizeof("struct ndpi_id_struct")
        checker.flow_tcp_size = ffi.sizeof("struct ndpi_flow_tcp_struct")
        checker.flow_udp_size = ffi.sizeof("struct ndpi_flow_udp_struct")
        dissector = lib.dissector_init(checker)
        if dissector == ffi.NULL:
            raise ValueError("Error while initializing dissector.")
        else:
            lib.dissector_configure(dissector)
    else:
        dissector = ffi.NULL
    return dissector


class NFMeter(Process):
    """ NFMeter for entries management """
    def __init__(self, observer_cfg, meter_cfg, channel):
        super().__init__()
        self.ffi, self.lib = create_context()
        self.observer = NFObserver(cfg=observer_cfg,
                                   ffi=self.ffi,
                                   lib=self.lib)
        self.idle_timeout = meter_cfg.idle_timeout
        self.active_timeout = meter_cfg.active_timeout
        self.accounting_mode = meter_cfg.accounting_mode
        self.udps = meter_cfg.udps
        self.n_dissections = meter_cfg.n_dissections
        self.statistics = meter_cfg.statistics
        self.channel = channel

    def run(self):
        """ run NFMeter main processing loop """
        meter_tick = 0
        meter_scan_tick = 0
        meter_scan_interval = 10
        idle_timeout = self.idle_timeout
        active_timeout = self.active_timeout
        accounting_mode = self.accounting_mode
        statistics = self.statistics
        n_dissections = self.n_dissections
        cache = NFCache()
        observer = self.observer
        channel = self.channel
        active_flows = 0
        ffi, lib = self.ffi, self.lib
        dissector = setup_dissector(ffi, lib, n_dissections)
        udps = self.udps
        sync = False
        if len(udps) > 0:  # streamer started with udps: sync internal structures on update.
            sync = True
        try:
            for observable_type, time, packet in observer:
                if observable_type == 1:
                    go_scan = False
                    if time - meter_scan_tick >= meter_scan_interval:
                        go_scan = True
                        meter_scan_tick = time
                    if time >= meter_tick:
                        meter_tick = time
                    diff = consume(packet, cache, active_timeout, idle_timeout, channel, ffi, lib, udps, sync,
                                   accounting_mode, n_dissections, statistics, dissector)
                    active_flows += diff
                    if go_scan:
                        idles = meter_scan(meter_tick, cache, idle_timeout, channel, udps, sync, n_dissections,
                                           statistics, ffi, lib, dissector)
                        active_flows -= idles
                else:
                    if time > meter_tick:
                        meter_tick = time
                    if time - meter_scan_tick >= meter_scan_interval:
                        idles = meter_scan(meter_tick, cache, idle_timeout, channel, udps, sync, n_dissections,
                                           statistics, ffi, lib, dissector)
                        active_flows -= idles
                        meter_scan_tick = time
            raise KeyboardInterrupt
        except KeyboardInterrupt:
            del observer
            meter_cleanup(cache, channel, udps, sync, n_dissections, statistics, ffi, lib, dissector)
            self.observer.close()
            self.lib.dissector_cleanup(dissector)
            del ffi
            del lib
            self.ffi.dlclose(self.lib)
