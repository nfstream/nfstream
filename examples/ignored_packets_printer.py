"""
------------------------------------------------------------------------------------------------------------------------
ignored_packets_printer.py
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

import sys
from nfstream import NFStreamer, NFPlugin


class IgnoredPacketsPrinter(NFPlugin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.num_packets = 0

    def on_init(self, packet, flow):
        self.num_packets += 1

    def on_update(self, packet, flow):
        self.num_packets += 1

    def on_ignore(self):
        self.num_packets += 1
        print(f"ignored packet {self.num_packets}")


if __name__ == '__main__':  # Mandatory if you are running on Windows Platform
    path = sys.argv[1]
    flow_streamer = NFStreamer(source=path,
                               statistical_analysis=False,
                               idle_timeout=1,
                               udps=IgnoredPacketsPrinter(),
                               n_meters=1)

    for flow in flow_streamer:
        pass
