"""
------------------------------------------------------------------------------------------------------------------------
extension_server.py
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

from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import namedtuple
import json
import sys

# yapf: disable
NFRequest = namedtuple('NFRequest', ['browser',
                                     'timestamp',
                                     'remote_ip',
                                     'tab_id',
                                     'request_id',
                                     'tab_is_active',
                                     'tab_url'])
# yapf: enable


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
            request = NFRequest(data["browser"],
                                float(data["timestamp"]),
                                data["ip_address"],
                                data["tab_id"],
                                data["req_id"],
                                data["tab_is_active"],
                                data["tab_url"])

            # For sake of brevity, we print it only
            print(request)
            # However you can use this server in a child process and poll from it using a Queue (channel)
            # self.server.channel.put(request)
        else:
            self.send_response(400)
            self._set_headers()

    def log_message(self, fmt, *args):
        return


class NFRequestServer(HTTPServer):
    """ NFRequest HTTP server"""
    def __init__(self, *args):
        HTTPServer.__init__(self, *args)
        self.stopped = False
        # self.channel = channel


if __name__ == '__main__':  # Mandatory if you are running on Windows Platform
    try:
        port = int(sys.argv[1])
    except IndexError:  # not specified
        port = 28314
    server_address = ('', port)   # localhost with configurable port
    server = NFRequestServer(server_address, NFRequestHandler)
    try:
        while not server.stopped:
            server.handle_request()
    except KeyboardInterrupt:
        exit(0)
