"""
------------------------------------------------------------------------------------------------------------------------
browser.py
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

# ----------------------------------------------------------------------------------------------------------------------
# IMPORTANT: THIS FEATURE IS EXPERIMENTAL AND STILL NOT INCLUDED AS PART OF THE OFFICIAL DOCUMENTATION.
# It is mainly an exploration of possible process name enrichment when system visibility mode is set.
# Browsers (chrome or firefox) that are generating traffic must be started with the nfstream browser extension.
# The basic idea is explore how to catch browser requests attributes (tab url for example) and try to map it to
# a flow entry based of remote IP.
# This is implemented by starting HTTP server that will listen to extension records (POSTs).
# ----------------------------------------------------------------------------------------------------------------------


from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import OrderedDict, namedtuple
from .utils import NFEvent
import time
import json


NFRequest = namedtuple('NFRequest', ['id',
                                     'browser',
                                     'remote_ip',
                                     'tab_url',
                                     'timestamp'])

browser_processes = ["chrome", "GeckoMain"]


class RequestCache(OrderedDict):
    def __init__(self, timeout, *args, **kwds):
        self.last_scan_time = 0
        self.timeout = timeout
        super().__init__(*args, **kwds)

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        value.sort(key=lambda x: x.timestamp)
        for idx, val in enumerate(value):
            if ((time.time() * 1000) - val.timestamp) >= self.timeout:
                del value[idx]
            else:
                break
        if not value:  # value is []
            del self[key]
        else:
            super().__setitem__(key, value)
            self.move_to_end(key)  # now this item is the most recently updated and sorted and idle are removed

    def __eq__(self, other):
        return super().__eq__(other)

    def get_lru_key(self):
        return next(iter(self))

    def scan(self):
        """ scan and delete LRU entries based on a defined timeout """
        remaining = True  # We suppose that there is something to expire
        go_scan = False
        current_time = time.time() * 1000
        if (current_time - self.last_scan_time) >= 10:
            self.last_scan_time = current_time
            go_scan = True
        while remaining and go_scan:
            try:
                lru_key = self.get_lru_key()  # will return the LRU conn key.
                lru_last_update_time = self[lru_key][-1].timestamp
                if current_time - lru_last_update_time >= self.timeout:  # expire it.
                    del self[lru_key]
                else:
                    remaining = False  # LRU flow is not yet idle.
            except StopIteration:  # Empty cache
                remaining = False

    @staticmethod
    def get_nearest_request_idx(requests, flow):
        """ return from a list of requests the nearest request to a flow based on timestamp and a grace time period """
        nearest = None
        if requests is not None:
            grace_time = 1000
            # grace time period: we are matching a flow to a request identified by remote ip and creation timestamp
            # we do not map a flow to request if the time diff is greater than grace_time in milliseconds
            min_time_diff_idx = 0
            min_time_diff = 18446744073709551615000  # handle idx 0
            for idx, request in enumerate(requests):
                time_diff = abs(request.timestamp - flow.bidirectional_first_seen_ms)
                if time_diff < min_time_diff:
                    min_time_diff = time_diff
                    min_time_diff_idx = idx
            if min_time_diff <= grace_time:
                nearest = min_time_diff_idx
        return nearest

    def match_flow(self, flow):
        requests = None
        src_ip = False
        try:
            requests = self[flow.dst_ip]
        except KeyError:
            try:
                requests = self[flow.src_ip]
                src_ip = True
            except KeyError:
                pass
        idx_request = self.get_nearest_request_idx(requests, flow)
        if idx_request is not None:
            flow.system_browser_tab = requests[idx_request].tab_url
            del requests[idx_request]
            if len(requests) == 0:
                if src_ip:
                    del self[flow.src_ip]
                else:
                    del self[flow.dst_ip]
        return flow


class NFRequestHandler(BaseHTTPRequestHandler):
    """ Handler for HTTP request from browser extension """
    def _set_headers(self):
        """ headers setter """
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header("Access-Control-Allow-Headers", "X-Requested-With")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.end_headers()

    def do_OPTIONS(self):
        """ OPTIONS handler """
        self.send_response(200)
        self._set_headers()

    def do_POST(self):
        """ POST handler """
        if self.path.endswith('.json') and (self.path.startswith('/nfstream-chrome') or
                                            self.path.startswith('/nfstream-firefox')):
            length = self.headers['content-length']
            data = json.loads(self.rfile.read(int(length)))
            self.send_response(200)
            self._set_headers()
            request = NFRequest(NFEvent.BROWSER_REQUEST,
                                data["browser"],
                                data["ip_address"],
                                data["tab_url"],
                                float(data["timestamp"]))
            self.server.channel.put(request)
        else:
            self.send_response(400)
            self._set_headers()

    def log_message(self, fmt, *args):
        return


class NFRequestServer(HTTPServer):
    """ NFRequest HTTP server"""
    def __init__(self, channel, *args):
        HTTPServer.__init__(self, *args)
        self.stopped = False
        self.channel = channel


def system_browser_workflow(channel, port):
    """ Process workflow for Browser request handling """
    server_address = ('', port)  # localhost with configurable port
    server = NFRequestServer(channel, server_address, NFRequestHandler)
    try:
        while not server.stopped:
            server.handle_request()
    except KeyboardInterrupt:
        return
