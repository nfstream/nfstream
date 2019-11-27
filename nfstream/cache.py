#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: cache.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from .plugin import valid_plugins, nfstream_core_plugins, ndpi_plugins, NFPlugin
from collections import OrderedDict
from .flow import NFFlow
import time as tm
import threading
import zmq


class LRU(OrderedDict):
    """ Thread safe least recently updated dict """
    def __init__(self, idle_timeout, *args, **kwds):
        super().__init__(*args, **kwds)
        self._lock = threading.Lock()
        self._idle_timeout = idle_timeout

    def __enter__(self):
        self._lock.acquire()  # we acquire lock
        return self

    def __exit__(self, type, value, traceback):
        self._lock.release()  # we release lock

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.move_to_end(key)  # now this item is the most recently updated

    def __eq__(self, other):
        return super().__eq__(o)

    def get_idle_item(self, current_tick, core, user):
        return self[next(iter(self))].idle(self._idle_timeout, current_tick, core, user)


class NFCache(object):
    """ NFCache for flows management """
    def __init__(self, observer=None, idle_timeout=30, active_timeout=300, nroots=512,
                 core_plugins=nfstream_core_plugins, user_plugins=(),
                 dissect=True, max_tcp_dissections=10, max_udp_dissections=16):
        self.observer = observer
        try:
            self.producer = zmq.Context().socket(zmq.PUSH)
            self.producer.bind('ipc:///tmp/nfstream.pipe')
        except zmq.error.ZMQError:
            raise OSError("NFStreamer failed to bind socket (producer).")
        self._roots = []  # root structure for flow caching: dict of LRUs
        self.nroots = nroots
        self.idle_timeout = idle_timeout * 1000
        self.active_timeout = active_timeout * 1000
        if self.idle_timeout < 0:
            self.idle_timeout = 0
        if self.active_timeout < 0:
            self.active_timeout = 0
        for root_idx in range(nroots):  # init root
            self._roots.append(LRU(idle_timeout=self.idle_timeout))
        self.idle_scan_period = 0.001
        self.idle_scanning = True
        self.current_tick = 0
        self.current_root_idx = 0  # current updating to avoid collision
        self.last_visited_root_idx = 0
        self.active_flows = 0
        self.idx_generator = 0
        self.processed_pkts = 0
        self.performances = [0, 0]
        # start idle walker
        self.idle_walker = threading.Thread(target=self.idle_scan, args=())
        self.idle_walker.daemon = True  # demonize thread
        self.idle_walker.start()
        self.stopped = False
        if dissect:
            self.core_plugins = core_plugins + ndpi_plugins + [NFPlugin(name='max_tcp_dissections',
                                                                        init_function=lambda p: max_tcp_dissections,
                                                                        volatile=True),
                                                               NFPlugin(name='max_udp_dissections',
                                                                        init_function=lambda p: max_udp_dissections,
                                                                        volatile=True)
                                                               ]
        else:
            self.core_plugins = core_plugins
        try:
            valid_plugins(user_plugins)
        except TypeError:
            raise TypeError("Streamer initiated with unknown type plugins (must be NFPlugin type).")
        except ValueError:
            raise TypeError("Streamer initiated with non unique plugins names. Consider renaming your added plugins.")
        self.user_plugins = user_plugins

    def idle_scan(self):
        while True:  # main loop
            tm.sleep(self.idle_scan_period)  # apply idle scan period (kind of micro pause)
            go_scan = self.idle_scanning
            if go_scan:
                remaining = True
                # still having idle flows to poll
                while remaining and self.last_visited_root_idx != self.current_root_idx:  # we do not scan fresh root
                    with self._roots[self.last_visited_root_idx] as root:
                        try:
                            idle_item = root.get_idle_item(self.current_tick, self.core_plugins, self.user_plugins)
                            if idle_item is not None:  # idle
                                self.producer.send_pyobj(idle_item)
                                del root[idle_item.nfhash]
                                self.active_flows -= 1  # remove it
                            else:
                                remaining = False  # no idle flows to poll
                        except StopIteration:
                            remaining = False  # root is empty
                        self.last_visited_root_idx += 1  # we move to next root
                        if self.last_visited_root_idx == self.nroots:
                            self.last_visited_root_idx = 0  # back to zero check
            else:
                break

    def terminate(self):
        """ terminate all entries in NFCache """
        self.idle_scanning = False  # deactivate scan_walker
        self.idle_walker.join()
        for root_idx in range(self.nroots):
            with self._roots[root_idx] as root:
                for h in list(root.keys()):
                    f = root[h].clean(self.core_plugins, self.user_plugins)
                    self.producer.send_pyobj(f)
                    self.active_flows -= 1
                    del root[h]
        self.observer.packet_generator.close()  # close generator
        self.producer.send_pyobj(None)

    def consume(self, ppkt):
        """ consume a parsed packet and produce flow """
        self.current_root_idx = ppkt.root_idx
        # classical create/update
        with self._roots[ppkt.root_idx] as root:
            try:  # update flow
                flow = root[ppkt.nfhash].update(ppkt,
                                                self.core_plugins,
                                                self.user_plugins,
                                                self.active_timeout)
                if flow is not None:
                    if flow.expiration_id < 0:  # custom expiration
                        self.producer.send_pyobj(flow)
                        del root[flow.nfhash]
                        self.active_flows -= 1
                    else:  # active expiration
                        parent_flow_id = flow.flow_id
                        self.producer.send_pyobj(flow)
                        del root[flow.nfhash]
                        root[ppkt.nfhash] = NFFlow(ppkt, self.core_plugins, self.user_plugins, parent_flow_id)
            except KeyError:  # create flow
                root[ppkt.nfhash] = NFFlow(ppkt, self.core_plugins, self.user_plugins, self.idx_generator)
                self.active_flows += 1
                self.idx_generator += 1

    def run(self):
        """ run NFCache main processing loop """
        for parsed_packet in self.observer:
            if not self.stopped:
                if parsed_packet is not None:
                    if parsed_packet.time >= self.current_tick:
                        self.current_tick = parsed_packet.time
                        self.consume(parsed_packet)
            else:
                break
        self.terminate()
