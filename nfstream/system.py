"""
------------------------------------------------------------------------------------------------------------------------
system.py
Copyright (C) 2019-22 - NFStream Developers
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

from collections import OrderedDict, namedtuple
from psutil import Process, net_connections
from .meter import get_flow_key
from socket import SocketKind
from .utils import NFEvent
import time


NFSocket = namedtuple("NFSocket", ["id", "key", "process_pid", "process_name"])


class ConnCache(OrderedDict):
    """LRU Connections Cache
    The ConnCache object is used to cache connections entries such as MRU entries are kept on the end and LRU entries
    will be at the start. Note that we use OrderedDict which leverages classical python dict combined with a doubly
    linked list with sentinel nodes to track order.
    By doing so, we can access in an efficient way idle connections entries that need to expired based on a timeout.
    """

    def __init__(self, channel, timeout, *args, **kwds):
        self.channel = channel
        self.timeout = timeout + 5000
        self.last_scan_time = 0
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

    def scan(self, current_time):
        """Scan and delete LRU entries based on a defined timeout"""
        if (current_time - self.last_scan_time) > 10:
            remaining = True  # We suppose that there is something to expire
            scanned = 0
            while (
                remaining and scanned <= 1000
            ):  # Each 10 ms we scan with 1000 entries budget
                try:
                    lru_key = self.get_lru_key()  # will return the LRU conn key.
                    lru_last_update_time = self[lru_key]
                    if current_time - lru_last_update_time >= self.timeout:
                        del self[lru_key]
                        self.channel.put(
                            NFSocket(NFEvent.SOCKET_REMOVE, lru_key, None, None)
                        )  # Send to streamer
                        scanned += 1
                    else:
                        remaining = False  # LRU flow is not yet idle.
                except StopIteration:  # Empty cache
                    remaining = False
            self.last_scan_time = current_time


def simplify_protocol(protocol):
    """Transform protocol IDs to 3 unique values: 6 for TCP, 17 for UDP and 0 for others"""
    if protocol == 6:
        return protocol
    if protocol == 17:
        return protocol
    return 0


def get_conn_key_from_flow(f):
    """Compute a conn key from NFlow object attributes"""
    return get_flow_key(
        f.src_ip, f.src_port, f.dst_ip, f.dst_port, simplify_protocol(f.protocol), 0, 0
    )


def match_flow_conn(conn_cache, flow):
    """Match a flow with a connection entry based on a shared key"""
    if len(conn_cache) > 0:
        flow_key = get_conn_key_from_flow(flow)
        try:
            flow_map_socket = conn_cache[flow_key]
            flow.system_process_name = flow_map_socket[0]
            flow.system_process_pid = flow_map_socket[1]
        except KeyError:
            pass
    return flow


def get_conn_key(c):
    """Create a 5-tuple connection key tuple"""
    if c.raddr != () and c.pid is not None:
        if c.type == SocketKind.SOCK_STREAM:  # TCP protocol
            return get_flow_key(
                c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, 6, 0, 0
            )
        if c.type == SocketKind.SOCK_DGRAM:  # UDP protocol
            return get_flow_key(
                c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, 17, 0, 0
            )
        return get_flow_key(c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, 0, 0, 0)
    return None


def system_socket_worflow(channel, idle_timeout, poll_period):
    """Host ground-truth generation workflow"""
    conn_cache = ConnCache(channel=channel, timeout=idle_timeout)
    try:
        while True:
            current_time = time.time() * 1000
            for conn in net_connections(kind="inet"):
                # IMPORTANT: The rationale behind the usage of an active polling approach (net_connections call):
                # System process visibility is intended to generate the most accurate ground truth for traffic
                # classification end-host-based research experiments, as reported in the literature [1].
                # Thus, it must be a cross-platform approach that works the same on Linux, macOS, and
                # Windows (Gaming traffic classification challenges). On Linux, things can be done more elegantly
                # using eBPF tracing exec calls or NetLink monitoring. However, this will requires specific
                # implementation for Linux versus Windows and proper handling of old kernel versions.
                # We prefer to keep it out of the nfstream codebase. As we use net_connections from psutil
                # (https://github.com/giampaolo/psutil) (https://github.com/giampaolo/psutil) Python package,
                # future work may include providing such enhancements to psutil project, and thus, a broader
                # community can benefit from it.
                # [1]: http://tomasz.bujlow.com/publications/2012_journal_TELFOR.pdf
                key = get_conn_key(conn)
                if key is not None:  # We succeeded to obtain a key.
                    if key not in conn_cache:  # Create and send
                        process_name = Process(conn.pid).name()
                        conn_cache[key] = current_time
                        channel.put(
                            NFSocket(NFEvent.SOCKET_CREATE, key, conn.pid, process_name)
                        )  # Send to streamer
                    else:  # update time
                        conn_cache[key] = current_time
            conn_cache.scan(current_time)

            time.sleep(poll_period)  # Sleep with configured poll period
            #                          0 will ensure the maximum active polling capacity and accuracy.
            #                          Greater values will results is less intensive CPU load and less accuracy.
            #                          A tradeoff must be decided (as always).
            #                          Completeness versus Polling frequency study (per protocol, per platform)
            #                          are provided in [1]
            #                          [2]: https://dl.acm.org/doi/abs/10.1145/1629607.1629610
    except KeyboardInterrupt:
        return
