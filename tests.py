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

import unittest
from nfstream import NFStreamer, NFPlugin
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
                        result[flow.application_name]['bytes'] += flow.total_bytes
                        result[flow.application_name]['flows'] += 1
                        result[flow.application_name]['pkts'] += flow.total_packets
                    except KeyError:
                        result[flow.application_name] = {"bytes": flow.total_bytes, 'flows': 1, 'pkts': flow.total_packets}
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
        streamer_test = NFStreamer(source='tests/pcap/facebook.pcap')
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

    def test_statistical_features(self):
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source='tests/pcap/google_ssl.pcap')
        flows = []
        for flow in streamer_test:
            flows.append(flow)
        del streamer_test
        self.assertEqual(flows[0].min_piat_ms, 0)
        self.assertEqual(flows[0].max_piat_ms, 995)
        self.assertEqual(flows[0].src2dst_min_piat_ms, 76)
        self.assertEqual(flows[0].src2dst_mean_piat_ms, 444.6666666666667)
        self.assertEqual(flows[0].src2dst_stdev_piat_ms, 398.80726017617934)
        self.assertEqual(flows[0].src2dst_max_piat_ms, 1185)
        self.assertEqual(flows[0].dst2src_min_piat_ms, 66)
        self.assertEqual(flows[0].dst2src_mean_piat_ms, 599.1818181818182)
        self.assertEqual(flows[0].dst2src_stdev_piat_ms, 384.78456782511904)
        self.assertEqual(flows[0].dst2src_max_piat_ms, 1213)
        print("{}\t: \033[94mOK\033[0m".format(".Testing statistical_features".ljust(60, ' ')))

    def test_noroot_live(self):
        print("\n----------------------------------------------------------------------")
        try:
            streamer_test = NFStreamer(idle_timeout=0)
        except SystemExit:
            print("{}\t: \033[94mOK\033[0m".format(".Testing live capture (noroot)".ljust(60, ' ')))

    def test_user_plugins(self):
        class feat_1(NFPlugin):
            def on_update(self, obs, entry):
                if entry.total_packets == 1:
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


if __name__ == '__main__':
    unittest.main()

