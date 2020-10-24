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
from .engine import create_engine
from .flow import NFlow
from .utils import set_affinity


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


def meter_scan(meter_tick, cache, idle_timeout, channel, udps, sync, n_dissections, statistics, splt, ffi, lib,
               dissector):
    remaining = True  # We suppose that there is something to expire
    scanned = 0
    while remaining and scanned < 1000:  # idle scan budget (each 10ms we scan 1000 as maximum)
        try:
            flow_key = cache.get_lru_key()  # will return the LRU flow key.
            flow = cache[flow_key]
            if flow.is_idle(meter_tick, idle_timeout):  # idle, expire it.
                channel.put(flow.expire(udps, sync, n_dissections, statistics, splt, ffi, lib, dissector))
                del cache[flow_key]
                del flow
                scanned += 1
            else:
                remaining = False  # LRU flow is not yet idle.
        except StopIteration:  # Empty cache
            remaining = False
    return scanned


def get_flow_key(packet, ffi):
    """ Create flow key from packet information (6-tuple) """
    src_ip = ffi.string(packet.src_ip_str).decode('utf-8', errors='ignore')
    dst_ip = ffi.string(packet.dst_ip_str).decode('utf-8', errors='ignore')
    return packet.protocol, packet.vlan_id, \
           min(src_ip, dst_ip), max(src_ip, dst_ip),\
           min(packet.src_port, packet.dst_port), max(packet.src_port, packet.dst_port)


def consume(packet, cache, active_timeout, idle_timeout, channel, ffi, lib, udps, sync, accounting_mode, n_dissections,
            statistics, splt, dissector):
    """ consume a packet and produce flow """
    # We maintain state for active flows computation 1 for creation, 0 for update/cut, -1 for custom expire
    flow_key = get_flow_key(packet, ffi)
    try:  # update flow
        flow = cache[flow_key].update(packet, idle_timeout, active_timeout, ffi, lib, udps, sync, accounting_mode,
                                      n_dissections, statistics, splt, dissector)
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
                                            statistics, splt, dissector)
                except OSError:
                    print("WARNING: Failed to allocate memory space for flow creation. Flow creation aborted.")
                state = 0
        else:
            state = 0
    except KeyError:  # create flow
        try:
            if sync:
                flow = NFlow(packet, ffi, lib, udps, sync, accounting_mode, n_dissections, statistics, splt, dissector)
                if flow.expiration_id == -1:  # A user Plugin forced expiration on the first packet
                    channel.put(flow.expire(udps, sync, n_dissections, statistics, splt, ffi, lib, dissector))
                    del flow
                    state = 0
                else:
                    cache[flow_key] = flow
                    state = 1
            else:
                cache[flow_key] = NFlow(packet, ffi, lib, udps, sync, accounting_mode, n_dissections, statistics, splt,
                                        dissector)
                state = 1
        except OSError:
            print("WARNING: Failed to allocate memory space for flow creation. Flow creation aborted.")
            state = 0
    return state


def meter_cleanup(cache, channel, udps, sync, n_dissections, statistics, splt, ffi, lib, dissector):
    """ cleanup all entries in NFCache """
    for flow_key in list(cache.keys()):
        flow = cache[flow_key]
        # Push it on channel.
        channel.put(flow.expire(udps, sync, n_dissections, statistics, splt, ffi, lib, dissector))
        del cache[flow_key]
        del flow


def setup_dissector(ffi, lib, n_dissections):
    """ Setup dissector according to dissections value """
    if n_dissections:  # Dissection activated
        # Check that headers and loaded library match and initiate dissector.
        checker = ffi.new("struct dissector_checker *")
        checker.flow_size = ffi.sizeof("struct ndpi_flow_struct")
        checker.id_size = ffi.sizeof("struct ndpi_id_struct")
        checker.flow_tcp_size = ffi.sizeof("struct ndpi_flow_tcp_struct")
        checker.flow_udp_size = ffi.sizeof("struct ndpi_flow_udp_struct")
        dissector = lib.dissector_init(checker)
        if dissector == ffi.NULL:
            raise ValueError("Error while initializing dissector.")
        # Configure it (activate bitmask to all protocols)
        lib.dissector_configure(dissector)
    else:  # No dissection configured
        dissector = ffi.NULL
    return dissector


def setup_capture(ffi, lib, root_idx, source, snaplen, promisc, mode, bpf_filter):
    """ Setup capture options """
    capture = lib.capture_open(bytes(source, 'utf-8'), mode, root_idx)
    if capture == ffi.NULL:
        return
    fanout_set_failed = lib.capture_set_fanout(capture, mode, root_idx)
    if fanout_set_failed:
        return
    timeout_set_failed = lib.capture_set_timeout(capture, mode, root_idx)
    if timeout_set_failed:
        return
    promisc_set_failed = lib.capture_set_promisc(capture, mode, root_idx, int(promisc))
    if promisc_set_failed:
        return
    snaplen_set_failed = lib.capture_set_snaplen(capture, mode, root_idx, snaplen)
    if snaplen_set_failed:
        return
    if bpf_filter is not None:
        filter_set_failed = lib.capture_set_filter(capture, bytes(bpf_filter, 'utf-8'), root_idx)
        if filter_set_failed:
            return
    return capture


def track(lib, capture, mode, interface_stats, tracker, processed, ignored):
    """ Update shared performance values """
    lib.capture_stats(capture, interface_stats, mode)
    tracker[0].value = interface_stats.dropped
    tracker[1].value = processed
    tracker[2].value = ignored


def meter_workflow(source, snaplen, decode_tunnels, bpf_filter, promisc, n_roots, root_idx, mode,
                   idle_timeout, active_timeout, accounting_mode, udps, n_dissections, statistics, splt,
                   channel, tracker, lock):
    """ Metering workflow """
    set_affinity(root_idx+1)
    ffi, lib = create_engine()
    capture = setup_capture(ffi, lib, root_idx, source, snaplen, promisc, mode, bpf_filter)
    if capture is None:
        ffi.dlclose(lib)
        channel.put(None)
        return
    meter_tick, meter_scan_tick, meter_track_tick = 0, 0, 0  # meter, idle scan and perf track timelines
    meter_scan_interval, meter_track_interval = 10, 1000  # we scan each 10 msecs and update perf each sec.
    cache = NFCache()
    dissector = setup_dissector(ffi, lib, n_dissections)
    active_flows, ignored_packets, processed_packets = 0, 0, 0
    sync = False
    if len(udps) > 0:  # streamer started with udps: sync internal structures on update.
        sync = True
    remaining_packets = True
    interface_stats = ffi.new("struct nf_stat *")
    # We ensure that processes start at the same time
    if root_idx == n_roots - 1:
        lock.release()
    else:
        lock.acquire()
        lock.release()
    activation_failed = lib.capture_activate(capture, mode, root_idx)
    if activation_failed:
        ffi.dlclose(lib)
        channel.put(None)
        return
    while remaining_packets:
        nf_packet = ffi.new("struct nf_packet *")
        ret = lib.capture_next(capture, nf_packet, decode_tunnels, n_roots, root_idx, mode)
        if ret > 0:  # Valid must be processed by meter
            packet_time = nf_packet.time
            if packet_time > meter_tick:
                meter_tick = packet_time
            else:
                nf_packet.time = meter_tick  # Force time order
            if ret == 1:  # Must be processed
                processed_packets += 1
                go_scan = False
                if meter_tick - meter_scan_tick >= meter_scan_interval:
                    go_scan = True  # Activate scan
                    meter_scan_tick = meter_tick
                # Consume packet and return diff
                diff = consume(nf_packet, cache, active_timeout, idle_timeout, channel, ffi, lib, udps, sync,
                               accounting_mode, n_dissections, statistics, splt, dissector)
                active_flows += diff
                if go_scan:
                    idles = meter_scan(meter_tick, cache, idle_timeout, channel, udps, sync, n_dissections,
                                       statistics, splt, ffi, lib, dissector)
                    active_flows -= idles
            else:  # time ticker
                if meter_tick - meter_scan_tick >= meter_scan_interval:
                    idles = meter_scan(meter_tick, cache, idle_timeout, channel, udps, sync, n_dissections,
                                       statistics, splt, ffi, lib, dissector)
                    active_flows -= idles
                    meter_scan_tick = meter_tick
        elif ret == 0:  # Ignored packet
            ignored_packets += 1
        elif ret == -1:  # Read error or empty buffer
            pass
        else:  # End of file
            remaining_packets = False  # end of loop
        if meter_tick - meter_track_tick >= meter_track_interval:  # Performance tracking
            track(lib, capture, mode, interface_stats, tracker, processed_packets, ignored_packets)
            meter_track_tick = meter_tick
    # Expire all remaining flows in the cache.
    meter_cleanup(cache, channel, udps, sync, n_dissections, statistics, splt, ffi, lib, dissector)
    # Close capture
    lib.capture_close(capture)
    # Clean dissector
    lib.dissector_cleanup(dissector)
    # Release engine library
    ffi.dlclose(lib)
    channel.put(None)
