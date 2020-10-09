#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
dhcp.py
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

from enum import Enum
import ipaddress
from nfstream import NFPlugin
import dpkt


class MsgType(Enum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NACK = 6
    RELEASE = 7
    INFORM = 8


class Dhcp(NFPlugin):
    """dhcp plugin

    This plugin extracts client information from DHCP sessions, and split flow
    on transaction completion to prevent several sessions to be considered as 
    the same flow. The following information are retrieved:

    - dhcp_12 (Option 12, hostname): hostname is decoded as utf8 with special characters being replaced.
    - dhcp_55 (Option 55, parameter request list): The list of options requested by the client on REQUEST messages.
    - dhcp_57 (Option 57, user class id)
    - dhcp_60 (Option 60, vendor class identifier)
    - dhcp_77 (Option 77, user class id)
    - dhcp_options: The list of options present in the REQUEST message.
    - dhcp_addr: The IP address allocated to the client

    This plugin depends on dpkt.
    """
    def on_init(self, packet, flow):
        flow.udps.dhcp_12 = None  # Sometimes hostname is missing from ndpi
        flow.udps.dhcp_55 = None  # Sometimes fingerprint is missing from ndpi
        flow.udps.dhcp_57 = None
        flow.udps.dhcp_60 = None
        flow.udps.dhcp_77 = None
        flow.udps.dhcp_options = []
        flow.udps.dhcp_addr = None

    def on_update(self, packet, flow):
        if flow.dst_port in [67, 68]:
            ip = dpkt.ip.IP(packet.ip_packet)
            udp = ip.data
            dhcp = dpkt.dhcp.DHCP(udp.data)
            msg_type = 0
            options = []

            for opt in dhcp.opts:
                if opt[0] == 12:  #  Hostname
                    hostname = opt[1].decode('utf-8', errors='replace')
                    if len(hostname) > 0:
                        flow.udps.dhcp_12 = hostname
                elif opt[0] == 53:  # Msg type
                    msg_type = MsgType(int.from_bytes(opt[1], "big"))
                elif opt[0] == 60:  # Vendor class identifier
                    flow.udps.dhcp_60 = opt[1].decode('utf-8')
                elif opt[0] == 77: # User class id
                    flow.udps.dhcp_77 = opt[1].decode('utf-8')
                elif opt[0] == 57:  # Maximum DHCP Message Size
                    flow.udps.dhcp_57 = int.from_bytes(opt[1], "big")
                elif opt[0] == 55:  # parameter request list (aka fingerprint)
                    opt55 = ','.join(str(i) for i in opt[1])
                options.append(opt[0])

            if msg_type == MsgType.REQUEST:
                flow.udps.dhcp_options = options
                flow.udps.dhcp_55 = opt55
            if msg_type in [MsgType.ACK, MsgType.NACK, MsgType.INFORM, MsgType.DECLINE]:
                flow.expiration_id = -1
            if msg_type == MsgType.ACK:
                flow.udps.dhcp_addr = ipaddress.ip_address(dhcp.yiaddr)  # your (client) ip address
