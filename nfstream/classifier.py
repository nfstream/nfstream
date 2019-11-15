#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: classifier.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from .ndpi_bindings import ndpi, NDPIProtocolBitMask, NDPIFlowStruct, NDPIProtocol, NDPIIdStruct
from .ndpi_bindings import ndpi_ndpi_finalize_initalization
from ctypes import pointer, memset, sizeof, cast, c_char_p, c_void_p, POINTER, c_uint8, addressof, byref
from datetime import datetime, timezone
import sys


class NFStreamClassifier:
    def __init__(self, name):
        self.name = name

    def on_flow_init(self, flow):
        return

    def on_flow_update(self, packet_information, flow, direction):
        return

    def on_flow_terminate(self, flow):
        return

    def on_exit(self):
        return


class NDPIClassifier(NFStreamClassifier):
    def __init__(self, name):
        NFStreamClassifier.__init__(self, name)
        if ndpi.ndpi_get_api_version() != ndpi.ndpi_wrap_get_api_version():
            sys.exit("nDPI Library version mismatch. Please make sure this code and the nDPI library are in sync.")
        self.ndpi_revision = cast(ndpi.ndpi_revision(), c_char_p).value.decode('utf-8')
        # print('NDPIClassifier.ndpi_revision: {}'.format(self.ndpi_revision))
        self.mod = ndpi.ndpi_init_detection_module()
        ndpi_ndpi_finalize_initalization(self.mod)
        all = NDPIProtocolBitMask()
        ndpi.ndpi_wrap_NDPI_BITMASK_SET_ALL(pointer(all))
        ndpi.ndpi_set_protocol_detection_bitmask2(self.mod, pointer(all))
        self.max_num_udp_dissected_pkts = 16
        self.max_num_tcp_dissected_pkts = 10

    @staticmethod
    def str(field):
        return cast(field, c_char_p).value.decode('utf-8', errors='ignore')

    def on_flow_init(self, flow):
        NFStreamClassifier.on_flow_init(self, flow)
        flow.classifiers[self.name]['ndpi_flow'] = NDPIFlowStruct()
        memset(byref(flow.classifiers[self.name]['ndpi_flow']), 0, sizeof(NDPIFlowStruct))
        flow.classifiers[self.name]['detected_protocol'] = NDPIProtocol()
        flow.classifiers[self.name]['detection_completed'] = 0
        flow.classifiers[self.name]['src_id'] = pointer(NDPIIdStruct())
        flow.classifiers[self.name]['dst_id'] = pointer(NDPIIdStruct())
        flow.classifiers[self.name]['application_name'] = ''
        flow.classifiers[self.name]['category_name'] = ''
        flow.classifiers[self.name]['guessed'] = 0

    def on_flow_update(self, packet_information, flow, direction):
        NFStreamClassifier.on_flow_update(self, packet_information, flow, direction)
        if flow.classifiers[self.name]['detection_completed'] == 0:  # process till not completed
            flow.classifiers[self.name]['detected_protocol'] = ndpi.ndpi_detection_process_packet(
                self.mod,
                byref(flow.classifiers[self.name]['ndpi_flow']),
                cast(cast(c_char_p(packet_information.raw), c_void_p), POINTER(c_uint8)),
                len(packet_information.raw),
                int(packet_information.timestamp),
                flow.classifiers[self.name]['src_id'],
                flow.classifiers[self.name]['dst_id']
            )

            enough_packets = ((flow.ip_protocol == 6) and ((flow.src_to_dst_pkts + flow.dst_to_src_pkts) >
                                                           self.max_num_tcp_dissected_pkts)) or \
                             ((flow.ip_protocol == 17) and ((flow.src_to_dst_pkts + flow.dst_to_src_pkts) >
                                                            self.max_num_udp_dissected_pkts))

            if enough_packets and flow.classifiers[self.name]['detected_protocol'].app_protocol == 0:
                # we reach max and still unknown, so give up!
                flow.classifiers[self.name]['detection_completed'] = 1
                flow.classifiers[self.name]['detected_protocol'] = ndpi.ndpi_detection_giveup(
                    self.mod,
                    byref(flow.classifiers[self.name]['ndpi_flow']),
                    1,
                    cast(addressof(c_uint8(0)), POINTER(c_uint8))
                )
                flow.classifiers[self.name]['guessed'] = 1
            # you can change flow.export_reason to a value > 2 and the flow will be terminated automatically

    def on_flow_terminate(self, flow):
        NFStreamClassifier.on_flow_terminate(self, flow)
        if flow.classifiers[self.name]['detected_protocol'].app_protocol == 0 and \
                flow.classifiers[self.name]['guessed'] == 0:  # didn't reach max and still unknown, so give up!
            flow.classifiers[self.name]['detected_protocol'] = ndpi.ndpi_detection_giveup(
                self.mod,
                byref(flow.classifiers[self.name]['ndpi_flow']),
                1,
                cast(addressof(c_uint8(0)), POINTER(c_uint8))
            )
            flow.classifiers[self.name]['guessed'] = 1

        master_name = self.str(
            ndpi.ndpi_get_proto_name(self.mod, flow.classifiers[self.name]['detected_protocol'].master_protocol)
        )
        app_name = self.str(
            ndpi.ndpi_get_proto_name(self.mod, flow.classifiers[self.name]['detected_protocol'].app_protocol)
        )
        category_name = self.str(
            ndpi.ndpi_category_get_name(self.mod, flow.classifiers[self.name]['detected_protocol'].category)
        )

        flow.classifiers[self.name]['application_name'] = master_name + '.' + app_name
        flow.classifiers[self.name]['category_name'] = category_name
        flow.classifiers[self.name]['app_id'] = flow.classifiers[self.name]['detected_protocol'].app_protocol
        flow.classifiers[self.name]['master_id'] = flow.classifiers[self.name]['detected_protocol'].master_protocol
        # Now we do move some values to flow.metrics just to print purpose. If you are implementing your magic
        # classifier, just do flow.classifiers['name_of_your_classifier]['name_of_your_feature']
        # if we move it before, it will trigger metrics callback.
        flow.metrics['application_name'] = flow.classifiers[self.name]['application_name']
        flow.metrics['category_name'] = flow.classifiers[self.name]['category_name']
        flow.metrics['http_dns_server_name'] = self.str(
            flow.classifiers[self.name]['ndpi_flow'].host_server_name
        )
        flow.metrics['tls_version'] = self.str(ndpi.ndpi_ssl_version2str(
            flow.classifiers[self.name]['ndpi_flow'].protos.stun_ssl.ssl.ssl_version, byref(c_uint8(0)))
        )
        flow.metrics['tls_client_server_name'] = self.str(
            flow.classifiers[self.name]['ndpi_flow'].protos.stun_ssl.ssl.client_certificate
        )
        flow.metrics['tls_server_server_name'] = self.str(
            flow.classifiers[self.name]['ndpi_flow'].protos.stun_ssl.ssl.server_certificate
        )
        flow.metrics['tls_server_organization'] = self.str(
            flow.classifiers[self.name]['ndpi_flow'].protos.stun_ssl.ssl.server_organization
        )
        flow.metrics['tls_not_before'] = str(datetime.fromtimestamp(
            flow.classifiers[self.name]['ndpi_flow'].protos.stun_ssl.ssl.notBefore, timezone.utc))
        flow.metrics['tls_not_after'] = str(datetime.fromtimestamp(
            flow.classifiers[self.name]['ndpi_flow'].protos.stun_ssl.ssl.notAfter, timezone.utc))
        del(flow.classifiers[self.name]['ndpi_flow'])

    def on_exit(self):
        NFStreamClassifier.on_exit(self)
        ndpi.ndpi_exit_detection_module(self.mod)