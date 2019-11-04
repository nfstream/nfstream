import unittest
from nfstream.streamer import Streamer
import os

""" flow export str representation """
flow_export_template = '''{ip_protocol},{ip_src},{src_port},{ip_dst},{dst_port},{ndpi_proto_num},\
{src_to_dst_pkts},{src_to_dst_bytes},{dst_to_src_pkts},{dst_to_src_bytes}'''


def test_src_to_dst_pkts(pkt_information, flow, direction):
    if direction == 0:
        new_value = flow.metrics['test_src_to_dst_pkts'] + 1
        return new_value
    else:
        return flow.metrics['test_src_to_dst_pkts']


def get_files_list(path):
    files = []
    for r, d, f in os.walk(path):
        for file in f:
            if '.out' in file:
                files.append(os.path.join(r, file))
    return files


def flows_from_file(file):
    f = open(file, "r")
    fl = f.readlines()
    truth = []
    for l in fl:
        truth.append(l.split("\n")[0])
    del fl
    f.close()
    return sorted(truth)


class TestMethods(unittest.TestCase):
    def test_no_unknown_protocols_without_timeouts(self):
        files = get_files_list("tests/out/")
        self.maxDif = None
        print("----------------------------------------------------------------------")
        print(".Testing on {} applications:".format(len(files)))
        for file in files:
            file_path = file.replace('.out', '').replace('/out/', '/pcap/')
            streamer_test = Streamer(source=file_path,
                                     capacity=64000,
                                     inactive_timeout=60000,
                                     active_timeout=60000, enable_ndpi=True)
            test_case_name = file_path.split('/')[-1].replace('.pcap', '')
            print(test_case_name + ': ')
            exports = []
            for export in streamer_test:
                if export.metrics["application_name"] != "Unknown.Unknown":
                    exports.append(flow_export_template.format(
                        ip_src=export.ip_src_str,
                        src_port=export.src_port,
                        ip_dst=export.ip_dst_str,
                        dst_port=export.dst_port,
                        ip_protocol=export.ip_protocol,
                        src_to_dst_pkts=export.src_to_dst_pkts,
                        dst_to_src_pkts=export.dst_to_src_pkts,
                        src_to_dst_bytes=export.src_to_dst_bytes,
                        dst_to_src_bytes=export.dst_to_src_bytes,
                        ndpi_proto_num=
                        str(export.classifiers['ndpi']['master_id']) + '.' + str(export.classifiers['ndpi']['app_id'])
                    ))
            exports = sorted(exports)
            exports_ground_truth = flows_from_file(file)
            del streamer_test
            self.assertEqual(exports, exports_ground_truth)
            print('PASS.')

    def test_streamer_capacity(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing warning Streamer capacity reached:")
        streamer_test = Streamer(source='tests/pcap/facebook.pcap',
                                 capacity=1,
                                 inactive_timeout=60000,
                                 active_timeout=60000)
        current_capacity = streamer_test.capacity
        streamer_test.capacity = current_capacity + 1
        current_capacity = streamer_test.capacity
        streamer_test.capacity = current_capacity - 1
        exports = list(streamer_test)
        del streamer_test
        self.assertEqual(exports[0].key, (520967716, 3232246546, 443, 44614, 0, 6))
        print('PASS.')

    def test_expiration_management(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing Streamer expiration management:")
        streamer_test = Streamer(source='tests/pcap/expiration/small_instagram.pcap',
                                 capacity=100,
                                 inactive_timeout=0,
                                 active_timeout=60000)
        exports = list(streamer_test)
        del streamer_test
        self.assertEqual(len(exports), 39)
        print('Inactive expiration: PASS.')

        streamer_test = Streamer(source='tests/pcap/expiration/small_instagram.pcap',
                                 capacity=100,
                                 inactive_timeout=60000,
                                 active_timeout=0)
        exports = list(streamer_test)
        del streamer_test
        self.assertEqual(len(exports), 39)
        print('Active expiration: PASS.')

    def test_flow_str_representation(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing Flow json representation:")
        streamer_test = Streamer(source='tests/pcap/expiration/small_instagram.pcap',
                                 capacity=100,
                                 inactive_timeout=60,
                                 active_timeout=120)
        exports = list(streamer_test)
        del streamer_test
        print(exports[0])
        print('Flow to json: PASS.')

    def test_adding_metric(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing user defined metric addition:")
        streamer_test = Streamer(source='tests/pcap/expiration/small_instagram.pcap',
                                 capacity=100,
                                 inactive_timeout=60,
                                 active_timeout=120,
                                 user_metrics={'test_src_to_dst_pkts': test_src_to_dst_pkts})
        exports = list(streamer_test)
        del streamer_test
        for export in exports:
            self.assertEqual(export.src_to_dst_pkts, export.metrics['test_src_to_dst_pkts'])
        print('user defined metric addition:  PASS.')

    def test_live_capture(self):
        print("\n----------------------------------------------------------------------")
        uid = os.getuid()
        print(".Testing live capture (uid={})".format(uid))
        if uid > 0:
            with self.assertRaises(SystemExit) as context:
                streamer_test = Streamer()
            self.assertEqual(type(context.exception), SystemExit)
            print("live capture (uid={}): PASS.".format(uid))
        else:
            streamer_test = Streamer(inactive_timeout=0)
            for export in streamer_test:
                break
            print("live capture (uid={}): PASS.".format(uid))

    def test_bpf_filter(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing bpf filtering:")
        bpf_filter = "tcp src port 44614"
        streamer_test = Streamer(source='tests/pcap/facebook.pcap',
                                 capacity=100,
                                 inactive_timeout=60,
                                 active_timeout=120,
                                 bpf_filter=bpf_filter)
        exports = list(streamer_test)
        self.assertEqual(len(exports), 1)
        print('bpf filteringt: PASS.')


if __name__ == '__main__':
    unittest.main()