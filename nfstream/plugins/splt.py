"""
------------------------------------------------------------------------------------------------------------------------
splt.py
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


class SPLT(NFPlugin):
    """
    Reimplementation of SPLT native analysis as NFPlugin: For testing and demo purposes.
    SPLT: Sequence of packet length and time analyzer.
    This plugin will take 2 arguments:
        - sequence_length: determines the maximum sequence length (number of packets to analyze)
        - accounting_mode: Set how packet size will be reported (0: raw_size,
                                                                 1: ip_size,
                                                                 2:transport_size,
                                                                 3:payload_size)
    Plugin will generate 3 new metrics as follows:
    - splt_directions: Array with direction of each packet (0: src_to_dst, 1:dst_to_src)
    - splt_ps: Array with packet size in bytes according to accounting_mode value.
    - splt_ipt: Array with inter packet arrival time in milliseconds.
    Note: Tail will be set with default value -1.
    """
    @staticmethod
    def _get_packet_size(packet, accounting_mode):
        if accounting_mode == 0:
            return packet.raw_size
        if accounting_mode == 1:
            return packet.ip_size
        if accounting_mode == 2:
            return packet.transport_size
        return packet.payload_size

    def on_init(self, packet, flow):
        flow.udps.splt_direction = [-1] * self.sequence_length
        flow.udps.splt_direction[0] = 0  # First packet so  src->dst
        flow.udps.splt_ps = [-1] * self.sequence_length
        flow.udps.splt_ps[0] = self._get_packet_size(packet, self.accounting_mode)
        flow.udps.splt_piat_ms = [-1] * self.sequence_length
        flow.udps.splt_piat_ms[0] = packet.delta_time

    def on_update(self, packet, flow):
        if flow.bidirectional_packets <= self.sequence_length:
            packet_index = flow.bidirectional_packets - 1
            flow.udps.splt_direction[packet_index] = packet.direction
            flow.udps.splt_ps[packet_index] = self._get_packet_size(packet, self.accounting_mode)
            flow.udps.splt_piat_ms[packet_index] = packet.delta_time
