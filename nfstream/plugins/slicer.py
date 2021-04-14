"""
------------------------------------------------------------------------------------------------------------------------
slicer.py
Copyright (C) 2019-21 - NFStream Developers
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

from nfstream import NFPlugin


class FlowSlicer(NFPlugin):
    """ FlowSlicer plugin

    This plugin implements a custom flow expiration logic based on a packets count limit.
    """
    def on_init(self, packet, flow):
        if self.limit == 1:
            flow.expiration_id = -1

    def on_update(self, packet, flow):
        if self.limit == flow.bidirectional_packets:
            flow.expiration_id = -1  # -1 value force expiration
