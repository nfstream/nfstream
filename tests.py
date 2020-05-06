#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: tests.py
This file is part of nfstream.

Copyright (C) 2019-20 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from nfstream import NFStreamer, NFPlugin
import unittest
import os
import csv


def get_files_list(path):
    files = []
    for r, d, f in os.walk(path):
        for file in f:
            if '.pcap' in file:
                files.append(os.path.join(r, file))
    return files


def get_app_dict(path):
    with open(path) as csvfile:
        reader = csv.DictReader(csvfile)
        app = {}
        for row in reader:
            try:
                app[row['ndpi_proto']]['bytes'] += int(row['s_to_c_bytes']) + int(row['c_to_s_bytes'])
                app[row['ndpi_proto']]['flows'] += 1
                app[row['ndpi_proto']]['pkts'] += int(row['s_to_c_pkts']) + int(row['c_to_s_pkts'])
            except KeyError:
                app[row['ndpi_proto']] = {"bytes": 0, "flows": 0, "pkts": 0}
                app[row['ndpi_proto']]["bytes"] += int(row['s_to_c_bytes']) + int(row['c_to_s_bytes'])
                app[row['ndpi_proto']]["flows"] += 1
                app[row['ndpi_proto']]['pkts'] += int(row['s_to_c_pkts']) + int(row['c_to_s_pkts'])
    return app


def build_ground_truth_dict(path):
    list_gt = get_files_list(path)
    ground_truth = {}
    for file in list_gt:
        ground_truth[file.split('/')[-1]] = get_app_dict(file)
    return ground_truth


class TestMethods(unittest.TestCase):
    def test_no_unknown_protocols_without_timeouts(self):
        files = get_files_list("tests/pcap/")
        ground_truth_ndpi = build_ground_truth_dict("tests/result/")
        print("\n----------------------------------------------------------------------")
        print(".Testing on {} applications:".format(len(files)))
        ok_files = []
        ko_files = []
        for test_file in files:
            streamer_test = NFStreamer(source=test_file, idle_timeout=60000, active_timeout=60000)
            test_case_name = test_file.split('/')[-1]
            result = {}
            for flow in streamer_test:
                if flow.application_name != 'Unknown':
                    try:
                        result[flow.application_name]['bytes'] += flow.bidirectional_raw_bytes
                        result[flow.application_name]['flows'] += 1
                        result[flow.application_name]['pkts'] += flow.bidirectional_packets
                    except KeyError:
                        result[flow.application_name] = {"bytes": flow.bidirectional_raw_bytes,
                                                         'flows': 1, 'pkts': flow.bidirectional_packets}
            if result == ground_truth_ndpi[test_case_name]:
                ok_files.append(test_case_name)
                print("{}\t: \033[94mOK\033[0m".format(test_case_name.ljust(60, ' ')))
            else:
                ko_files.append(test_case_name)
                print("{}\t: \033[31mKO\033[0m".format(test_case_name.ljust(60, ' ')))
            del streamer_test
        self.assertEqual(len(files), len(ok_files))

    def test_expiration_management(self):
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source='tests/pcap/facebook.pcap', active_timeout=0)
        flows = []
        for flow in streamer_test:
            flows.append(flow)
        self.assertEqual(len(flows), 60)
        print("{}\t: \033[94mOK\033[0m".format(".Testing Streamer expiration management".ljust(60, ' ')))

    def test_flow_metadata_extraction(self):
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source='tests/pcap/facebook.pcap', bpf_filter="src port 52066 or dst port 52066")
        flows = []
        for flow in streamer_test:
            flows.append(flow)
        del streamer_test
        self.assertEqual(flows[0].client_info, 'facebook.com')
        self.assertEqual(flows[0].server_info, '*.facebook.com,*.facebook.net,*.fb.com,*.fbcdn.net,*.fbsbx.com,\
*.m.facebook.com,*.messenger.com,*.xx.fbcdn.net,*.xy.fbcdn.net,*.xz.fbcdn.net,facebook.com,fb.com,\
messenger.com')
        self.assertEqual(flows[0].client_info, 'facebook.com')
        self.assertEqual(flows[0].j3a_client, 'bfcc1a3891601edb4f137ab7ab25b840')
        self.assertEqual(flows[0].j3a_server, '2d1eb5817ece335c24904f516ad5da12')
        print("{}\t: \033[94mOK\033[0m".format(".Testing metadata extraction".ljust(60, ' ')))

    def test_unfound_device(self):
        print("\n----------------------------------------------------------------------")
        try:
            streamer_test = NFStreamer(source="inexisting_file.pcap")
        except SystemExit:
            print("{}\t: \033[94mOK\033[0m".format(".Testing unfoud device".ljust(60, ' ')))

    def test_statistical_features_with_pad(self):
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source='tests/pcap/google_ssl.pcap', statistics=True, account_ip_padding_size=True)
        flows = []
        for flow in streamer_test:
            flows.append(flow)
        del streamer_test
        self.assertEqual(flows[0].id, 0)
        self.assertEqual(flows[0].bidirectional_first_seen_ms, 1434443394683)
        self.assertEqual(flows[0].bidirectional_last_seen_ms, 1434443401353)
        self.assertEqual(flows[0].src2dst_first_seen_ms, 1434443394683)
        self.assertEqual(flows[0].src2dst_last_seen_ms, 1434443401353)
        self.assertEqual(flows[0].dst2src_first_seen_ms, 1434443394717)
        self.assertEqual(flows[0].dst2src_last_seen_ms, 1434443401308)
        self.assertEqual(flows[0].version, 4)
        self.assertEqual(flows[0].src_port, 42835)
        self.assertEqual(flows[0].dst_port, 443)
        self.assertEqual(flows[0].protocol, 6)
        self.assertEqual(flows[0].vlan_id, 4)
        self.assertEqual(flows[0].src_ip, '172.31.3.224')
        self.assertEqual(flows[0].dst_ip, '216.58.212.100')
        self.assertEqual(flows[0].bidirectional_packets, 28)
        self.assertEqual(flows[0].bidirectional_raw_bytes, 9108)
        self.assertEqual(flows[0].bidirectional_ip_bytes, 8716)
        self.assertEqual(flows[0].bidirectional_duration_ms, 6670)
        self.assertEqual(flows[0].src2dst_packets, 16)
        self.assertEqual(flows[0].src2dst_raw_bytes, 1512)
        self.assertEqual(flows[0].src2dst_ip_bytes, 1288)
        self.assertEqual(flows[0].src2dst_duration_ms, 6670)
        self.assertEqual(flows[0].dst2src_packets, 12)
        self.assertEqual(flows[0].dst2src_raw_bytes, 7596)
        self.assertEqual(flows[0].dst2src_ip_bytes, 7428)
        self.assertEqual(flows[0].dst2src_duration_ms, 6591)
        self.assertEqual(flows[0].expiration_id, 0)
        self.assertEqual(flows[0].bidirectional_min_raw_ps, 54)
        self.assertEqual(flows[0].bidirectional_mean_raw_ps, 325.2857142857144)
        self.assertEqual(flows[0].bidirectional_stdev_raw_ps, 500.14981882416123)
        self.assertEqual(flows[0].bidirectional_max_raw_ps, 1484)
        self.assertEqual(flows[0].src2dst_min_raw_ps, 54)
        self.assertEqual(flows[0].src2dst_mean_raw_ps, 94.5)
        self.assertEqual(flows[0].src2dst_stdev_raw_ps, 89.55519713189923)
        self.assertEqual(flows[0].src2dst_max_raw_ps, 368)
        self.assertEqual(flows[0].dst2src_min_raw_ps, 60)
        self.assertEqual(flows[0].dst2src_mean_raw_ps, 632.9999999999999)
        self.assertEqual(flows[0].dst2src_stdev_raw_ps, 649.8457159552985)
        self.assertEqual(flows[0].dst2src_max_raw_ps, 1484)
        self.assertEqual(flows[0].bidirectional_min_ip_ps, 40)
        self.assertEqual(flows[0].bidirectional_mean_ip_ps, 311.2857142857144)
        self.assertEqual(flows[0].bidirectional_stdev_ip_ps, 500.14981882416123)
        self.assertEqual(flows[0].bidirectional_max_ip_ps, 1470)
        self.assertEqual(flows[0].src2dst_min_ip_ps, 40)
        self.assertEqual(flows[0].src2dst_mean_ip_ps, 80.49999999999999)
        self.assertEqual(flows[0].src2dst_stdev_ip_ps, 89.55519713189922)
        self.assertEqual(flows[0].src2dst_max_ip_ps, 354)
        self.assertEqual(flows[0].dst2src_min_ip_ps, 46)
        self.assertEqual(flows[0].dst2src_mean_ip_ps, 618.9999999999999)
        self.assertEqual(flows[0].dst2src_stdev_ip_ps, 649.8457159552985)
        self.assertEqual(flows[0].dst2src_max_ip_ps, 1470)
        self.assertEqual(flows[0].bidirectional_min_piat_ms, 0)
        self.assertEqual(flows[0].bidirectional_mean_piat_ms, 247.037037037037)
        self.assertEqual(flows[0].bidirectional_stdev_piat_ms, 324.04599406227237)
        self.assertEqual(flows[0].bidirectional_max_piat_ms, 995)
        self.assertEqual(flows[0].src2dst_min_piat_ms, 76)
        self.assertEqual(flows[0].src2dst_mean_piat_ms, 444.6666666666667)
        self.assertEqual(flows[0].src2dst_stdev_piat_ms, 398.80726017617934)
        self.assertEqual(flows[0].src2dst_max_piat_ms, 1185)
        self.assertEqual(flows[0].dst2src_min_piat_ms, 66)
        self.assertEqual(flows[0].dst2src_mean_piat_ms, 599.1818181818182)
        self.assertEqual(flows[0].dst2src_stdev_piat_ms, 384.78456782511904)
        self.assertEqual(flows[0].dst2src_max_piat_ms, 1213)
        self.assertEqual(flows[0].master_protocol, 91)
        self.assertEqual(flows[0].app_protocol, 126)
        self.assertEqual(flows[0].application_name, 'TLS.Google')
        self.assertEqual(flows[0].category_name, 'Web')
        self.assertEqual(flows[0].client_info, '')
        self.assertEqual(flows[0].server_info, '')
        self.assertEqual(flows[0].j3a_client, '')
        self.assertEqual(flows[0].j3a_server, '')
        self.assertEqual(flows[0].bidirectional_syn_packets, 2)
        self.assertEqual(flows[0].bidirectional_cwr_packets, 0)
        self.assertEqual(flows[0].bidirectional_ece_packets, 0)
        self.assertEqual(flows[0].bidirectional_urg_packets, 0)
        self.assertEqual(flows[0].bidirectional_ack_packets, 27)
        self.assertEqual(flows[0].bidirectional_psh_packets, 8)
        self.assertEqual(flows[0].bidirectional_rst_packets, 0)
        self.assertEqual(flows[0].bidirectional_fin_packets, 2)
        self.assertEqual(flows[0].src2dst_syn_packets, 1)
        self.assertEqual(flows[0].src2dst_cwr_packets, 0)
        self.assertEqual(flows[0].src2dst_ece_packets, 0)
        self.assertEqual(flows[0].src2dst_urg_packets, 0)
        self.assertEqual(flows[0].src2dst_ack_packets, 15)
        self.assertEqual(flows[0].src2dst_psh_packets, 4)
        self.assertEqual(flows[0].src2dst_rst_packets, 0)
        self.assertEqual(flows[0].src2dst_fin_packets, 1)
        self.assertEqual(flows[0].dst2src_syn_packets, 1)
        self.assertEqual(flows[0].dst2src_cwr_packets, 0)
        self.assertEqual(flows[0].dst2src_ece_packets, 0)
        self.assertEqual(flows[0].dst2src_urg_packets, 0)
        self.assertEqual(flows[0].dst2src_ack_packets, 12)
        self.assertEqual(flows[0].dst2src_psh_packets, 4)
        self.assertEqual(flows[0].dst2src_rst_packets, 0)
        self.assertEqual(flows[0].dst2src_fin_packets, 1)
        print("{}\t: \033[94mOK\033[0m".format(".Testing statistical features with ip padding".ljust(60, ' ')))

    def test_statistical_features_without_pad(self):
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source='tests/pcap/google_ssl.pcap', statistics=True)
        flows = []
        for flow in streamer_test:
            flows.append(flow)
        del streamer_test
        self.assertEqual(flows[0].id, 0)
        self.assertEqual(flows[0].bidirectional_first_seen_ms, 1434443394683)
        self.assertEqual(flows[0].bidirectional_last_seen_ms, 1434443401353)
        self.assertEqual(flows[0].src2dst_first_seen_ms, 1434443394683)
        self.assertEqual(flows[0].src2dst_last_seen_ms, 1434443401353)
        self.assertEqual(flows[0].dst2src_first_seen_ms, 1434443394717)
        self.assertEqual(flows[0].dst2src_last_seen_ms, 1434443401308)
        self.assertEqual(flows[0].version, 4)
        self.assertEqual(flows[0].src_port, 42835)
        self.assertEqual(flows[0].dst_port, 443)
        self.assertEqual(flows[0].protocol, 6)
        self.assertEqual(flows[0].vlan_id, 4)
        self.assertEqual(flows[0].src_ip, '172.31.3.224')
        self.assertEqual(flows[0].dst_ip, '216.58.212.100')
        self.assertEqual(flows[0].bidirectional_packets, 28)
        self.assertEqual(flows[0].bidirectional_raw_bytes, 9108)
        self.assertEqual(flows[0].bidirectional_ip_bytes, 8696)
        self.assertEqual(flows[0].bidirectional_duration_ms, 6670)
        self.assertEqual(flows[0].src2dst_packets, 16)
        self.assertEqual(flows[0].src2dst_raw_bytes, 1512)
        self.assertEqual(flows[0].src2dst_ip_bytes, 1288)
        self.assertEqual(flows[0].src2dst_duration_ms, 6670)
        self.assertEqual(flows[0].dst2src_packets, 12)
        self.assertEqual(flows[0].dst2src_raw_bytes, 7596)
        self.assertEqual(flows[0].dst2src_ip_bytes, 7408)
        self.assertEqual(flows[0].dst2src_duration_ms, 6591)
        self.assertEqual(flows[0].expiration_id, 0)
        self.assertEqual(flows[0].bidirectional_min_raw_ps, 54)
        self.assertEqual(flows[0].bidirectional_mean_raw_ps, 325.2857142857144)
        self.assertEqual(flows[0].bidirectional_stdev_raw_ps, 500.14981882416123)
        self.assertEqual(flows[0].bidirectional_max_raw_ps, 1484)
        self.assertEqual(flows[0].src2dst_min_raw_ps, 54)
        self.assertEqual(flows[0].src2dst_mean_raw_ps, 94.5)
        self.assertEqual(flows[0].src2dst_stdev_raw_ps, 89.55519713189923)
        self.assertEqual(flows[0].src2dst_max_raw_ps, 368)
        self.assertEqual(flows[0].dst2src_min_raw_ps, 60)
        self.assertEqual(flows[0].dst2src_mean_raw_ps, 632.9999999999999)
        self.assertEqual(flows[0].dst2src_stdev_raw_ps, 649.8457159552985)
        self.assertEqual(flows[0].dst2src_max_raw_ps, 1484)
        self.assertEqual(flows[0].bidirectional_min_ip_ps, 40)
        self.assertEqual(flows[0].bidirectional_mean_ip_ps, 310.57142857142856)
        self.assertEqual(flows[0].bidirectional_stdev_ip_ps, 500.54617788019937)
        self.assertEqual(flows[0].bidirectional_max_ip_ps, 1470)
        self.assertEqual(flows[0].src2dst_min_ip_ps, 40)
        self.assertEqual(flows[0].src2dst_mean_ip_ps, 80.49999999999999)
        self.assertEqual(flows[0].src2dst_stdev_ip_ps, 89.55519713189922)
        self.assertEqual(flows[0].src2dst_max_ip_ps, 354)
        self.assertEqual(flows[0].dst2src_min_ip_ps, 40)
        self.assertEqual(flows[0].dst2src_mean_ip_ps, 617.3333333333334)
        self.assertEqual(flows[0].dst2src_stdev_ip_ps, 651.4524099458397)
        self.assertEqual(flows[0].dst2src_max_ip_ps, 1470)
        self.assertEqual(flows[0].bidirectional_min_piat_ms, 0)
        self.assertEqual(flows[0].bidirectional_mean_piat_ms, 247.037037037037)
        self.assertEqual(flows[0].bidirectional_stdev_piat_ms, 324.04599406227237)
        self.assertEqual(flows[0].bidirectional_max_piat_ms, 995)
        self.assertEqual(flows[0].src2dst_min_piat_ms, 76)
        self.assertEqual(flows[0].src2dst_mean_piat_ms, 444.6666666666667)
        self.assertEqual(flows[0].src2dst_stdev_piat_ms, 398.80726017617934)
        self.assertEqual(flows[0].src2dst_max_piat_ms, 1185)
        self.assertEqual(flows[0].dst2src_min_piat_ms, 66)
        self.assertEqual(flows[0].dst2src_mean_piat_ms, 599.1818181818182)
        self.assertEqual(flows[0].dst2src_stdev_piat_ms, 384.78456782511904)
        self.assertEqual(flows[0].dst2src_max_piat_ms, 1213)
        self.assertEqual(flows[0].master_protocol, 91)
        self.assertEqual(flows[0].app_protocol, 126)
        self.assertEqual(flows[0].application_name, 'TLS.Google')
        self.assertEqual(flows[0].category_name, 'Web')
        self.assertEqual(flows[0].client_info, '')
        self.assertEqual(flows[0].server_info, '')
        self.assertEqual(flows[0].j3a_client, '')
        self.assertEqual(flows[0].j3a_server, '')
        self.assertEqual(flows[0].bidirectional_syn_packets, 2)
        self.assertEqual(flows[0].bidirectional_cwr_packets, 0)
        self.assertEqual(flows[0].bidirectional_ece_packets, 0)
        self.assertEqual(flows[0].bidirectional_urg_packets, 0)
        self.assertEqual(flows[0].bidirectional_ack_packets, 27)
        self.assertEqual(flows[0].bidirectional_psh_packets, 8)
        self.assertEqual(flows[0].bidirectional_rst_packets, 0)
        self.assertEqual(flows[0].bidirectional_fin_packets, 2)
        self.assertEqual(flows[0].src2dst_syn_packets, 1)
        self.assertEqual(flows[0].src2dst_cwr_packets, 0)
        self.assertEqual(flows[0].src2dst_ece_packets, 0)
        self.assertEqual(flows[0].src2dst_urg_packets, 0)
        self.assertEqual(flows[0].src2dst_ack_packets, 15)
        self.assertEqual(flows[0].src2dst_psh_packets, 4)
        self.assertEqual(flows[0].src2dst_rst_packets, 0)
        self.assertEqual(flows[0].src2dst_fin_packets, 1)
        self.assertEqual(flows[0].dst2src_syn_packets, 1)
        self.assertEqual(flows[0].dst2src_cwr_packets, 0)
        self.assertEqual(flows[0].dst2src_ece_packets, 0)
        self.assertEqual(flows[0].dst2src_urg_packets, 0)
        self.assertEqual(flows[0].dst2src_ack_packets, 12)
        self.assertEqual(flows[0].dst2src_psh_packets, 4)
        self.assertEqual(flows[0].dst2src_rst_packets, 0)
        self.assertEqual(flows[0].dst2src_fin_packets, 1)
        print("{}\t: \033[94mOK\033[0m".format(".Testing statistical features without ip padding".ljust(60, ' ')))

    def test_noroot_live(self):
        print("\n----------------------------------------------------------------------")
        try:
            streamer_test = NFStreamer(source="lo", idle_timeout=0)
        except SystemExit:
            print("{}\t: \033[94mOK\033[0m".format(".Testing live capture (noroot)".ljust(60, ' ')))

    def test_bad_observer_args(self):
        print("\n----------------------------------------------------------------------")
        try:
            streamer_test = NFStreamer(source=1, promisc=53, snaplen="wrong", bpf_filter=False,
                                       account_ip_padding_size="toto",
                                       decode_tunnels=22)
        except SystemExit as e:
            self.assertEqual(str(e).count("\n"), 6)
        print("{}\t: \033[94mOK\033[0m".format(".Testing parameters handling".ljust(60, ' ')))

    def test_user_plugins(self):
        class feat_1(NFPlugin):
            def on_update(self, obs, entry):
                if entry.bidirectional_packets == 1:
                    entry.feat_1 == obs.length

        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source='tests/pcap/facebook.pcap', plugins=[feat_1()])
        for flow in streamer_test:
            if flow.id == 0:
                self.assertEqual(flow.feat_1, 0)
            else:
                self.assertEqual(flow.feat_1, 0)
        del streamer_test
        print("{}\t: \033[94mOK\033[0m".format(".Testing adding user plugins".ljust(60, ' ')))

    def test_bpf_filter(self):
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source='tests/pcap/facebook.pcap',
                                   statistics=True,
                                   bpf_filter="src port 52066 or dst port 52066")
        count = 0
        for flow in streamer_test:
            print(flow)
            print(flow.to_namedtuple())
            print(flow.to_json())
            count = count + 1
            self.assertEqual(flow.src_port, 52066)
        self.assertEqual(count, 1)
        del streamer_test
        print("{}\t: \033[94mOK\033[0m".format(".Testing BPF filtering".ljust(60, ' ')))

    def test_to_pandas(self):
        print("\n----------------------------------------------------------------------")
        df = NFStreamer(source='tests/pcap/facebook.pcap', statistics=True,
                        bpf_filter="src port 52066 or dst port 52066").to_pandas()
        self.assertEqual(df["src_port"][0], 52066)
        self.assertEqual(df.shape[0], 1)
        self.assertEqual(df.shape[1], 95)
        print("{}\t: \033[94mOK\033[0m".format(".Testing to Pandas".ljust(60, ' ')))


if __name__ == '__main__':
    unittest.main()

