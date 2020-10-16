"""
------------------------------------------------------------------------------------------------------------------------
mdns.py
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

from nfstream import NFPlugin
import dpkt


class MDNS(NFPlugin):
    """ MDNS plugin

    This plugin extracts answer information from MDNS requests. The following information are retrieved:

    - mdns_ptr: An ordered list of PTR answsers.

    """
    def on_init(self, packet, flow):
        flow.udps.mdns_ptr = []
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if flow.dst_port == 5353:
            try:
                ip = dpkt.ip.IP(packet.ip_packet)
                udp = ip.data
                dns = dpkt.dns.DNS(udp.data)
            except (dpkt.NeedData, dpkt.UnpackError):
                return

            if len(dns.an) > 0:
                for answer in dns.an:
                    if answer.type == 12:  # PTR
                        ptr = answer.ptrname.replace(',', ' ')
                        if ptr not in flow.udps.mdns_ptr:
                            flow.udps.mdns_ptr.append(ptr)
