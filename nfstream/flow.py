"""
------------------------------------------------------------------------------------------------------------------------
flow.py
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

from collections import namedtuple
from math import sqrt
from .utils import NFEvent

# When NFStream is extended with plugins, packer C structure is pythonized using the following namedtuple.
nf_packet = namedtuple(
    "NFPacket",
    [
        "time",
        "delta_time",
        "direction",
        "raw_size",
        "ip_size",
        "transport_size",
        "payload_size",
        "src_ip",
        "src_mac",
        "src_oui",
        "dst_ip",
        "dst_mac",
        "dst_oui",
        "src_port",
        "dst_port",
        "protocol",
        "vlan_id",
        "ip_version",
        "ip_packet",
        "syn",
        "cwr",
        "ece",
        "urg",
        "ack",
        "psh",
        "rst",
        "fin",
        "tunnel_id",
    ],
)


class UDPS(object):
    """dummy class that add udps slot the flexibility required for extensions"""


def pythonize_packet(packet, ffi, flow):
    """convert a cdata packet to a namedtuple"""
    src_ip = flow.src_ip
    dst_ip = flow.dst_ip
    src_mac = flow.src_mac
    dst_mac = flow.dst_mac
    src_oui = flow.src_oui
    dst_oui = flow.dst_oui
    if packet.direction:
        src_ip = flow.dst_ip
        dst_ip = flow.src_ip
        src_mac = flow.dst_mac
        dst_mac = flow.src_mac
        src_oui = flow.dst_oui
        dst_oui = flow.src_oui

    return nf_packet(
        time=packet.time,
        delta_time=packet.delta_time,
        direction=packet.direction,
        raw_size=packet.raw_size,
        ip_size=packet.ip_size,
        transport_size=packet.transport_size,
        payload_size=packet.payload_size,
        src_ip=src_ip,
        src_mac=src_mac,
        src_oui=src_oui,
        dst_ip=dst_ip,
        dst_mac=dst_mac,
        dst_oui=dst_oui,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
        vlan_id=packet.vlan_id,
        ip_version=packet.ip_version,
        ip_packet=bytes(ffi.buffer(packet.ip_content, packet.ip_content_len)),
        syn=packet.syn,
        cwr=packet.cwr,
        ece=packet.ece,
        urg=packet.urg,
        ack=packet.ack,
        psh=packet.psh,
        rst=packet.rst,
        fin=packet.fin,
        tunnel_id=packet.tunnel_id,
    )


class NFlow(object):
    """
    NFlow is NFStream representation of a network flow.
    It is a slotted class for performances reasons, and slots are initiated according to NFStream detected mode.
    If nfstream is used with extension, we refer to it as sync mode, and we need to update slots from C structure.
    If not, nfstream will compute all configured metrics within C structure and update it only at init and expire.
    Such logic allows us to provide maximum performances when running without extensions. When set with extension
    we pay the cost of flexibility with attributes access/update.

    """

    __slots__ = (
        "id",
        "expiration_id",
        "src_ip",
        "src_mac",
        "src_oui",
        "src_port",
        "dst_ip",
        "dst_mac",
        "dst_oui",
        "dst_port",
        "protocol",
        "ip_version",
        "vlan_id",
        "tunnel_id",
        "bidirectional_first_seen_ms",
        "bidirectional_last_seen_ms",
        "bidirectional_duration_ms",
        "bidirectional_packets",
        "bidirectional_bytes",
        "src2dst_first_seen_ms",
        "src2dst_last_seen_ms",
        "src2dst_duration_ms",
        "src2dst_packets",
        "src2dst_bytes",
        "dst2src_first_seen_ms",
        "dst2src_last_seen_ms",
        "dst2src_duration_ms",
        "dst2src_packets",
        "dst2src_bytes",
        "bidirectional_min_ps",
        "bidirectional_mean_ps",
        "bidirectional_stddev_ps",
        "bidirectional_max_ps",
        "src2dst_min_ps",
        "src2dst_mean_ps",
        "src2dst_stddev_ps",
        "src2dst_max_ps",
        "dst2src_min_ps",
        "dst2src_mean_ps",
        "dst2src_stddev_ps",
        "dst2src_max_ps",
        "bidirectional_min_piat_ms",
        "bidirectional_mean_piat_ms",
        "bidirectional_stddev_piat_ms",
        "bidirectional_max_piat_ms",
        "src2dst_min_piat_ms",
        "src2dst_mean_piat_ms",
        "src2dst_stddev_piat_ms",
        "src2dst_max_piat_ms",
        "dst2src_min_piat_ms",
        "dst2src_mean_piat_ms",
        "dst2src_stddev_piat_ms",
        "dst2src_max_piat_ms",
        "bidirectional_syn_packets",
        "bidirectional_cwr_packets",
        "bidirectional_ece_packets",
        "bidirectional_urg_packets",
        "bidirectional_ack_packets",
        "bidirectional_psh_packets",
        "bidirectional_rst_packets",
        "bidirectional_fin_packets",
        "src2dst_syn_packets",
        "src2dst_cwr_packets",
        "src2dst_ece_packets",
        "src2dst_urg_packets",
        "src2dst_ack_packets",
        "src2dst_psh_packets",
        "src2dst_rst_packets",
        "src2dst_fin_packets",
        "dst2src_syn_packets",
        "dst2src_cwr_packets",
        "dst2src_ece_packets",
        "dst2src_urg_packets",
        "dst2src_ack_packets",
        "dst2src_psh_packets",
        "dst2src_rst_packets",
        "dst2src_fin_packets",
        "splt_direction",
        "splt_ps",
        "splt_piat_ms",
        "application_name",
        "application_category_name",
        "application_is_guessed",
        "application_confidence",
        "requested_server_name",
        "client_fingerprint",
        "server_fingerprint",
        "user_agent",
        "content_type",
        "_C",
        "udps",
        "system_process_pid",
        "system_process_name",
        "system_browser_tab",
    )

    def __init__(
        self,
        packet,
        ffi,
        lib,
        udps,
        sync,
        accounting_mode,
        n_dissections,
        statistics,
        splt,
        dissector,
        decode_tunnels,
        system_visibility_mode,
    ):
        self.id = (
            NFEvent.FLOW
        )  # id set to NFLOW for internal communications and handled (incremented) by NFStreamer.
        self.expiration_id = 0
        # Initialize C structure.
        self._C = lib.meter_initialize_flow(
            packet, accounting_mode, statistics, splt, n_dissections, dissector, sync
        )
        if self._C == ffi.NULL:  # raise OSError in order to be handled by meter.
            raise OSError("Not enough memory for new flow creation.")
        # Here we go for the first copy in order to make defined slots available
        self.src_ip = ffi.string(self._C.src_ip_str).decode("utf-8", errors="ignore")
        self.src_mac = ffi.string(self._C.src_mac_str).decode("utf-8", errors="ignore")
        self.src_oui = ffi.string(self._C.src_oui).decode("utf-8", errors="ignore")
        self.src_port = self._C.src_port
        self.dst_ip = ffi.string(self._C.dst_ip_str).decode("utf-8", errors="ignore")
        self.dst_mac = ffi.string(self._C.dst_mac_str).decode("utf-8", errors="ignore")
        self.dst_oui = ffi.string(self._C.dst_oui).decode("utf-8", errors="ignore")
        self.dst_port = self._C.dst_port
        self.protocol = self._C.protocol
        self.ip_version = self._C.ip_version
        self.vlan_id = self._C.vlan_id
        self.bidirectional_first_seen_ms = self._C.bidirectional_first_seen_ms
        self.bidirectional_last_seen_ms = self._C.bidirectional_last_seen_ms
        self.bidirectional_duration_ms = self._C.bidirectional_duration_ms
        self.bidirectional_packets = self._C.bidirectional_packets
        self.bidirectional_bytes = self._C.bidirectional_bytes
        self.src2dst_first_seen_ms = self._C.src2dst_first_seen_ms
        self.src2dst_last_seen_ms = self._C.src2dst_last_seen_ms
        self.src2dst_duration_ms = self._C.src2dst_duration_ms
        self.src2dst_packets = self._C.src2dst_packets
        self.src2dst_bytes = self._C.src2dst_bytes
        self.dst2src_first_seen_ms = self._C.dst2src_first_seen_ms
        self.dst2src_last_seen_ms = self._C.dst2src_last_seen_ms
        self.dst2src_duration_ms = self._C.dst2src_duration_ms
        self.dst2src_packets = self._C.dst2src_packets
        self.dst2src_bytes = self._C.dst2src_bytes
        if decode_tunnels:
            self.tunnel_id = self._C.tunnel_id
        if statistics:  # if statistical analysis set, we activate statistical slots.
            self.bidirectional_min_ps = self._C.bidirectional_min_ps
            self.bidirectional_mean_ps = self._C.bidirectional_mean_ps
            self.bidirectional_stddev_ps = self._C.bidirectional_stddev_ps
            self.bidirectional_max_ps = self._C.bidirectional_max_ps
            self.src2dst_min_ps = self._C.src2dst_min_ps
            self.src2dst_mean_ps = self._C.src2dst_mean_ps
            self.src2dst_stddev_ps = self._C.src2dst_stddev_ps
            self.src2dst_max_ps = self._C.src2dst_max_ps
            self.dst2src_min_ps = self._C.dst2src_min_ps
            self.dst2src_mean_ps = self._C.dst2src_mean_ps
            self.dst2src_stddev_ps = self._C.dst2src_stddev_ps
            self.dst2src_max_ps = self._C.dst2src_max_ps
            self.bidirectional_min_piat_ms = self._C.bidirectional_min_piat_ms
            self.bidirectional_mean_piat_ms = self._C.bidirectional_mean_piat_ms
            self.bidirectional_stddev_piat_ms = self._C.bidirectional_stddev_piat_ms
            self.bidirectional_max_piat_ms = self._C.bidirectional_max_piat_ms
            self.src2dst_min_piat_ms = self._C.src2dst_min_piat_ms
            self.src2dst_mean_piat_ms = self._C.src2dst_mean_piat_ms
            self.src2dst_stddev_piat_ms = self._C.src2dst_stddev_piat_ms
            self.src2dst_max_piat_ms = self._C.src2dst_max_piat_ms
            self.dst2src_min_piat_ms = self._C.dst2src_min_piat_ms
            self.dst2src_mean_piat_ms = self._C.dst2src_mean_piat_ms
            self.dst2src_stddev_piat_ms = self._C.dst2src_stddev_piat_ms
            self.dst2src_max_piat_ms = self._C.dst2src_max_piat_ms
            self.bidirectional_syn_packets = self._C.bidirectional_syn_packets
            self.bidirectional_cwr_packets = self._C.bidirectional_cwr_packets
            self.bidirectional_ece_packets = self._C.bidirectional_ece_packets
            self.bidirectional_urg_packets = self._C.bidirectional_urg_packets
            self.bidirectional_ack_packets = self._C.bidirectional_ack_packets
            self.bidirectional_psh_packets = self._C.bidirectional_psh_packets
            self.bidirectional_rst_packets = self._C.bidirectional_rst_packets
            self.bidirectional_fin_packets = self._C.bidirectional_fin_packets
            self.src2dst_syn_packets = self._C.src2dst_syn_packets
            self.src2dst_cwr_packets = self._C.src2dst_cwr_packets
            self.src2dst_ece_packets = self._C.src2dst_ece_packets
            self.src2dst_urg_packets = self._C.src2dst_urg_packets
            self.src2dst_ack_packets = self._C.src2dst_ack_packets
            self.src2dst_psh_packets = self._C.src2dst_psh_packets
            self.src2dst_rst_packets = self._C.src2dst_rst_packets
            self.src2dst_fin_packets = self._C.src2dst_fin_packets
            self.dst2src_syn_packets = self._C.dst2src_syn_packets
            self.dst2src_cwr_packets = self._C.dst2src_cwr_packets
            self.dst2src_ece_packets = self._C.dst2src_ece_packets
            self.dst2src_urg_packets = self._C.dst2src_urg_packets
            self.dst2src_ack_packets = self._C.dst2src_ack_packets
            self.dst2src_psh_packets = self._C.dst2src_psh_packets
            self.dst2src_rst_packets = self._C.dst2src_rst_packets
            self.dst2src_fin_packets = self._C.dst2src_fin_packets
        if n_dissections:  # Same for dissection when > 0
            if sync:
                self.application_name = ffi.string(self._C.application_name).decode(
                    "utf-8", errors="ignore"
                )
                self.application_category_name = ffi.string(
                    self._C.category_name
                ).decode("utf-8", errors="ignore")
                self.application_is_guessed = self._C.guessed
                self.application_confidence = self._C.confidence
                self.requested_server_name = ffi.string(
                    self._C.requested_server_name
                ).decode("utf-8", errors="ignore")
                self.client_fingerprint = ffi.string(self._C.c_hash).decode(
                    "utf-8", errors="ignore"
                )
                self.server_fingerprint = ffi.string(self._C.s_hash).decode(
                    "utf-8", errors="ignore"
                )
                self.user_agent = ffi.string(self._C.user_agent).decode(
                    "utf-8", errors="ignore"
                )
                self.content_type = ffi.string(self._C.content_type).decode(
                    "utf-8", errors="ignore"
                )
            else:
                self.application_name = None
                self.application_category_name = None
                self.application_is_guessed = None
                self.application_confidence = None
                self.requested_server_name = None
                self.client_fingerprint = None
                self.server_fingerprint = None
                self.user_agent = None
                self.content_type = None
        if splt:  # If splt_analysis set (>0), we unpack the arrays structures.
            self.splt_direction = ffi.unpack(self._C.splt_direction, splt)
            self.splt_ps = ffi.unpack(self._C.splt_ps, splt)
            self.splt_piat_ms = ffi.unpack(self._C.splt_piat_ms, splt)
        if sync:  # NFStream running with Plugins
            self.udps = UDPS()
            for udp in udps:  # on_init entrypoint
                udp.on_init(pythonize_packet(packet, ffi, self), self)
        if system_visibility_mode > 0:
            self.system_process_pid = -1
            self.system_process_name = ""
            if system_visibility_mode == 2:
                self.system_browser_tab = ""

    def update(
        self,
        packet,
        idle_timeout,
        active_timeout,
        ffi,
        lib,
        udps,
        sync,
        accounting_mode,
        n_dissections,
        statistics,
        splt,
        dissector,
    ):
        """NFlow update method"""
        # First, we update internal C structure.
        ret = lib.meter_update_flow(
            self._C,
            packet,
            idle_timeout,
            active_timeout,
            accounting_mode,
            statistics,
            splt,
            n_dissections,
            dissector,
            sync,
        )
        if (
            ret > 0
        ):  # If update done it will be zero, idle and active are matched to 1 and 2.
            self.expiration_id = ret - 1
            return self.expire(
                udps, sync, n_dissections, statistics, splt, ffi, lib, dissector
            )  # expire it.
        if sync:  # If running with Plugins
            self.sync(n_dissections, statistics, splt, ffi, lib, sync)
            # We need to copy computed values on C struct.
            for udp in udps:  # Then call each plugin on_update entrypoint.
                udp.on_update(pythonize_packet(packet, ffi, self), self)
            if (
                self.expiration_id == -1
            ):  # One of the plugins set expiration to custom value (-1)
                return self.expire(
                    udps, sync, n_dissections, statistics, splt, ffi, lib, dissector
                )  # Expire it.

    def expire(self, udps, sync, n_dissections, statistics, splt, ffi, lib, dissector):
        """NFlow expiration method"""
        # Call expiration of C structure.
        lib.meter_expire_flow(self._C, n_dissections, dissector)
        # Then sync (second copy in case of non sync mode)
        self.sync(n_dissections, statistics, splt, ffi, lib, sync)
        if sync:  # Running with NFPlugins
            for udp in udps:
                udp.on_expire(self)  # Call each Plugin on_expire entrypoint
        lib.meter_free_flow(self._C, n_dissections, splt, 1)  # then free C struct
        del self._C  # and remove it from NFlow slots.
        return self

    def sync(self, n_dissections, statistics, splt, ffi, lib, sync_mode):
        """
        NFlow synchronizer method
           Will be called only twice when running without Plugins
           Will be called at each update when running with Plugins
        """
        self.bidirectional_last_seen_ms = self._C.bidirectional_last_seen_ms
        self.bidirectional_duration_ms = self._C.bidirectional_duration_ms
        self.bidirectional_packets = self._C.bidirectional_packets
        self.bidirectional_bytes = self._C.bidirectional_bytes
        self.src2dst_last_seen_ms = self._C.src2dst_last_seen_ms
        self.src2dst_duration_ms = self._C.src2dst_duration_ms
        self.src2dst_packets = self._C.src2dst_packets
        self.src2dst_bytes = self._C.src2dst_bytes
        self.dst2src_first_seen_ms = self._C.dst2src_first_seen_ms
        self.dst2src_last_seen_ms = self._C.dst2src_last_seen_ms
        self.dst2src_duration_ms = self._C.dst2src_duration_ms
        self.dst2src_packets = self._C.dst2src_packets
        self.dst2src_bytes = self._C.dst2src_bytes
        if statistics:  # Statistical analysis activated
            self.bidirectional_min_ps = self._C.bidirectional_min_ps
            self.bidirectional_mean_ps = self._C.bidirectional_mean_ps
            bidirectional_packets = self.bidirectional_packets
            # NOTE: We need the root square of the variance to provide sample stddev (Var**0.5)/(n-1)
            if bidirectional_packets > 1:
                self.bidirectional_stddev_ps = sqrt(
                    self._C.bidirectional_stddev_ps / (bidirectional_packets - 1)
                )
            self.bidirectional_max_ps = self._C.bidirectional_max_ps
            self.src2dst_min_ps = self._C.src2dst_min_ps
            self.src2dst_mean_ps = self._C.src2dst_mean_ps
            src2dst_packets = self.src2dst_packets
            if src2dst_packets > 1:
                self.src2dst_stddev_ps = sqrt(
                    self._C.src2dst_stddev_ps / (src2dst_packets - 1)
                )
            self.src2dst_max_ps = self._C.src2dst_max_ps
            self.dst2src_min_ps = self._C.dst2src_min_ps
            self.dst2src_mean_ps = self._C.dst2src_mean_ps
            dst2src_packets = self.dst2src_packets
            if dst2src_packets > 1:
                self.dst2src_stddev_ps = sqrt(
                    self._C.dst2src_stddev_ps / (dst2src_packets - 1)
                )
            self.dst2src_max_ps = self._C.dst2src_max_ps
            self.bidirectional_min_piat_ms = self._C.bidirectional_min_piat_ms
            self.bidirectional_mean_piat_ms = self._C.bidirectional_mean_piat_ms
            if bidirectional_packets > 2:
                self.bidirectional_stddev_piat_ms = sqrt(
                    self._C.bidirectional_stddev_piat_ms / (bidirectional_packets - 2)
                )
            self.bidirectional_max_piat_ms = self._C.bidirectional_max_piat_ms
            self.src2dst_min_piat_ms = self._C.src2dst_min_piat_ms
            self.src2dst_mean_piat_ms = self._C.src2dst_mean_piat_ms
            if src2dst_packets > 2:
                self.src2dst_stddev_piat_ms = sqrt(
                    self._C.src2dst_stddev_piat_ms / (src2dst_packets - 2)
                )
            self.src2dst_max_piat_ms = self._C.src2dst_max_piat_ms
            self.dst2src_min_piat_ms = self._C.dst2src_min_piat_ms
            self.dst2src_mean_piat_ms = self._C.dst2src_mean_piat_ms
            if dst2src_packets > 2:
                self.dst2src_stddev_piat_ms = sqrt(
                    self._C.dst2src_stddev_piat_ms / (dst2src_packets - 2)
                )
            self.dst2src_max_piat_ms = self._C.dst2src_max_piat_ms
            self.bidirectional_syn_packets = self._C.bidirectional_syn_packets
            self.bidirectional_cwr_packets = self._C.bidirectional_cwr_packets
            self.bidirectional_ece_packets = self._C.bidirectional_ece_packets
            self.bidirectional_urg_packets = self._C.bidirectional_urg_packets
            self.bidirectional_ack_packets = self._C.bidirectional_ack_packets
            self.bidirectional_psh_packets = self._C.bidirectional_psh_packets
            self.bidirectional_rst_packets = self._C.bidirectional_rst_packets
            self.bidirectional_fin_packets = self._C.bidirectional_fin_packets
            self.src2dst_syn_packets = self._C.src2dst_syn_packets
            self.src2dst_cwr_packets = self._C.src2dst_cwr_packets
            self.src2dst_ece_packets = self._C.src2dst_ece_packets
            self.src2dst_urg_packets = self._C.src2dst_urg_packets
            self.src2dst_ack_packets = self._C.src2dst_ack_packets
            self.src2dst_psh_packets = self._C.src2dst_psh_packets
            self.src2dst_rst_packets = self._C.src2dst_rst_packets
            self.src2dst_fin_packets = self._C.src2dst_fin_packets
            self.dst2src_syn_packets = self._C.dst2src_syn_packets
            self.dst2src_cwr_packets = self._C.dst2src_cwr_packets
            self.dst2src_ece_packets = self._C.dst2src_ece_packets
            self.dst2src_urg_packets = self._C.dst2src_urg_packets
            self.dst2src_ack_packets = self._C.dst2src_ack_packets
            self.dst2src_psh_packets = self._C.dst2src_psh_packets
            self.dst2src_rst_packets = self._C.dst2src_rst_packets
            self.dst2src_fin_packets = self._C.dst2src_fin_packets
        if n_dissections:  # If dissection set (>0)
            # We minimize updates to a single one, when detection completed.
            if self._C.detection_completed < 2:
                self.application_name = ffi.string(self._C.application_name).decode(
                    "utf-8", errors="ignore"
                )
                self.application_category_name = ffi.string(
                    self._C.category_name
                ).decode("utf-8", errors="ignore")
                self.requested_server_name = ffi.string(
                    self._C.requested_server_name
                ).decode("utf-8", errors="ignore")
                self.client_fingerprint = ffi.string(self._C.c_hash).decode(
                    "utf-8", errors="ignore"
                )
                self.server_fingerprint = ffi.string(self._C.s_hash).decode(
                    "utf-8", errors="ignore"
                )
                self.user_agent = ffi.string(self._C.user_agent).decode(
                    "utf-8", errors="ignore"
                )
                self.content_type = ffi.string(self._C.content_type).decode(
                    "utf-8", errors="ignore"
                )
                self.application_is_guessed = self._C.guessed
                self.application_confidence = self._C.confidence
        if splt:
            if (
                sync_mode
            ):  # Same for splt, once we reach splt limit, there is no need to sync it anymore.
                if self._C.bidirectional_packets <= splt:
                    self.splt_direction = ffi.unpack(self._C.splt_direction, splt)
                    self.splt_ps = ffi.unpack(self._C.splt_ps, splt)
                    self.splt_piat_ms = ffi.unpack(self._C.splt_piat_ms, splt)
                else:
                    if (
                        self._C.splt_closed == 0
                    ):  # we also release the memory to keep only the obtained list.
                        lib.meter_free_flow(
                            self._C, n_dissections, splt, 0
                        )  # free SPLT
            else:
                self.splt_direction = ffi.unpack(self._C.splt_direction, splt)
                self.splt_ps = ffi.unpack(self._C.splt_ps, splt)
                self.splt_piat_ms = ffi.unpack(self._C.splt_piat_ms, splt)
                # Memory will be released by freer.

    def is_idle(self, tick, idle_timeout):
        """is_idle method to check if NFlow is idle accoring to configured timeout"""
        return (tick - idle_timeout) >= self._C.bidirectional_last_seen_ms

    def __str__(self):
        """String representation of NFlow"""
        started = False
        printable = "NFlow("
        for attr_name in self.__slots__:
            try:
                if not started:
                    printable += attr_name + "=" + str(getattr(self, attr_name))
                    started = True
                else:
                    if attr_name == "udps":
                        for udp_name in self.udps.__dict__.keys():
                            printable += (
                                ",\n      "
                                + attr_name
                                + "."
                                + udp_name
                                + "="
                                + str(getattr(self.udps, udp_name))
                            )
                    else:
                        printable += (
                            ",\n      "
                            + attr_name
                            + "="
                            + str(getattr(self, attr_name))
                        )
            except AttributeError:
                pass
        printable += ")"
        return printable

    def keys(self):
        """get NFlow keys"""
        # Note we transform udps to udps.value_name as preprocessing for csv/pandas interfaces
        ret = []
        for attr_name in self.__slots__:
            try:
                getattr(self, attr_name)
                if attr_name == "udps":
                    for udp_name in self.udps.__dict__.keys():
                        ret.append(attr_name + "." + udp_name)
                else:
                    ret.append(attr_name)
            except AttributeError:
                pass
        return ret

    def values(self):
        """get flow values"""
        # Note: same indexing as keys.
        ret = []
        for attr_name in self.__slots__:
            try:
                attr_value = getattr(self, attr_name)
                if attr_name == "udps":
                    for udp_value in self.udps.__dict__.values():
                        ret.append(udp_value)
                else:
                    ret.append(attr_value)
            except AttributeError:
                pass
        return ret
