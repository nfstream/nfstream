from .ndpi_bindings import ndpi, NDPI_PROTOCOL_BITMASK, ndpi_flow_struct, ndpi_protocol, ndpi_id_struct
from ctypes import pointer, memset, sizeof, cast, c_char_p, c_void_p, POINTER, c_uint8, addressof, byref
from datetime import datetime, timezone


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
        self.mod = ndpi.ndpi_init_detection_module()
        all = NDPI_PROTOCOL_BITMASK()
        ndpi.ndpi_wrap_NDPI_BITMASK_SET_ALL(pointer(all))
        ndpi.ndpi_set_protocol_detection_bitmask2(self.mod, pointer(all))
        self.max_num_udp_dissected_pkts = 16
        self.max_num_tcp_dissected_pkts = 10

    @staticmethod
    def str(field):
        return cast(field, c_char_p).value.decode('utf-8', errors='ignore')

    def on_flow_init(self, flow):
        NFStreamClassifier.on_flow_init(self, flow)
        flow.classifiers[self.name]['ndpi_flow'] = ndpi_flow_struct()
        memset(byref(flow.classifiers[self.name]['ndpi_flow']), 0, sizeof(ndpi_flow_struct))
        flow.classifiers[self.name]['detected_protocol'] = ndpi_protocol()
        flow.classifiers[self.name]['detection_completed'] = 0
        flow.classifiers[self.name]['src_id'] = pointer(ndpi_id_struct())
        flow.classifiers[self.name]['dst_id'] = pointer(ndpi_id_struct())
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