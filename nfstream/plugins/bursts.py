"""
------------------------------------------------------------------------------------------------------------------------
bursts.py
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

from nfstream import NFPlugin


class BurstSequence(NFPlugin):
    """Export the first N directional bursts of payload-carrying packets.

    A burst ends when the next nonempty payload travels in the other
    direction. Positive bytes denote src-to-dst and negative bytes dst-to-src.
    Unused entries are zero. Empty transport acknowledgements do not split bursts.
    """

    def __init__(self, sequence_length=10):
        if not isinstance(sequence_length, int) or sequence_length < 1:
            raise ValueError("sequence_length must be a positive integer")
        super().__init__(sequence_length=sequence_length)

    def on_init(self, packet, flow):
        flow.udps.burst_bytes = [0] * self.sequence_length
        flow.udps.burst_packets = [0] * self.sequence_length
        flow.udps.burst_index = -1
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        size = packet.payload_size
        index = flow.udps.burst_index
        if size == 0 or index == self.sequence_length:
            return
        if index == -1 or (flow.udps.burst_bytes[index] < 0) != bool(packet.direction):
            index += 1
            flow.udps.burst_index = index
            if index == self.sequence_length:
                return
        flow.udps.burst_bytes[index] += -size if packet.direction else size
        flow.udps.burst_packets[index] += 1

    def on_expire(self, flow):
        del flow.udps.burst_index
