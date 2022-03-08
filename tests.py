"""
------------------------------------------------------------------------------------------------------------------------
tests.py
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

import unittest
import pandas as pd
import json
import os
from nfstream import NFStreamer
from nfstream.plugins import SPLT, DHCP, FlowSlicer, MDNS
from termcolor import colored


def get_files_list(path):
    files = []
    for r, d, f in os.walk(path):
        for file in f:
            if '.pcap' == file[-5:] or ".pcapng" == file[-7:]:  # Pick out only pcaps files
                files.append(os.path.join(r, file))
    files.sort()
    return files


class TestMethods(unittest.TestCase):

    def test_source_parameter(self):
        print("\n----------------------------------------------------------------------")
        source = ["inexisting.pcap", "lo", 11]
        for x in source:
            with self.assertRaises(ValueError):
                NFStreamer(source=x).to_pandas()
        print("{}\t: {}".format(".Test source parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_decode_tunnels_parameter(self):
        print("\n----------------------------------------------------------------------")
        decode_tunnels = [33, "True"]
        for x in decode_tunnels:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           decode_tunnels=x)
        print("{}\t: {}".format(".Test decode_tunnels parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_bpf_filter_parameter(self):
        print("\n----------------------------------------------------------------------")
        bpf_filter = ["my filter", 11]
        for x in bpf_filter:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           bpf_filter=x).to_pandas()
        print("{}\t: {}".format(".Test bpf_filter parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_promiscuous_mode_parameter(self):
        print("\n----------------------------------------------------------------------")
        promiscuous_mode = ["yes", 89]
        for x in promiscuous_mode:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           promiscuous_mode=x)
        print("{}\t: {}".format(".Test promiscuous_mode parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_snapshot_length_parameter(self):
        print("\n----------------------------------------------------------------------")
        snapshot_length = ["largest", -1]
        for x in snapshot_length:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           snapshot_length=x)
        print("{}\t: {}".format(".Test snapshot_length parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_idle_timeout_parameter(self):
        print("\n----------------------------------------------------------------------")
        idle_timeout = [-1, "idle"]
        for x in idle_timeout:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           idle_timeout=x)
        print("{}\t: {}".format(".Test idle_timeout parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_active_timeout_parameter(self):
        print("\n----------------------------------------------------------------------")
        active_timeout = [-1, "active"]
        for x in active_timeout:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           active_timeout=x)
        print("{}\t: {}".format(".Test active_timeout parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_accounting_mode_parameter(self):
        print("\n----------------------------------------------------------------------")
        accounting_mode = [-1, 5, 'ip']
        for x in accounting_mode:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           accounting_mode=x)
        print("{}\t: {}".format(".Test accounting_mode parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_udps_parameter(self):
        print("\n----------------------------------------------------------------------")
        udps = [lambda y: y+1, "NFPlugin"]
        for x in udps:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           udps=x)
        print("{}\t: {}".format(".Test udps parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_n_dissections_parameter(self):
        print("\n----------------------------------------------------------------------")
        n_dissections = ["yes", -1, 256]
        for x in n_dissections:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           n_dissections=x)
        print("{}\t: {}".format(".Test n_dissections parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_system_visibility_mode_parameter(self):
        print("\n----------------------------------------------------------------------")
        system_visibility_mode = ["yes", -1, 3]
        for x in system_visibility_mode:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           system_visibility_mode=x)
        print("{}\t: {}".format(".Test system_visibility_mode parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_system_visibility_extension_port(self):
        print("\n----------------------------------------------------------------------")
        system_visibility_mode = ["yes", -1, 88888]
        for x in system_visibility_mode:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           system_visibility_extension_port=x)
        print("{}\t: {}".format(".Test system_visibility_extension_port parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_system_visibility_poll_ms(self):
        print("\n----------------------------------------------------------------------")
        system_visibility_mode = ["yes", -1]
        for x in system_visibility_mode:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           system_visibility_poll_ms=x)
        print("{}\t: {}".format(".Test system_visibility_poll_ms parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_statistical_analysis_parameter(self):
        print("\n----------------------------------------------------------------------")
        statistical_analysis = ["yes", 89]
        for x in statistical_analysis:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           statistical_analysis=x)
        print("{}\t: {}".format(".Test statistical_analysis parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_splt_analysis_parameter(self):
        print("\n----------------------------------------------------------------------")
        splt_analysis = [-1, 256, "yes"]
        for x in splt_analysis:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           splt_analysis=x)
        print("{}\t: {}".format(".Test splt_analysis parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_n_meters_parameter(self):
        print("\n----------------------------------------------------------------------")
        n_meters = ["yes", -1]
        for x in n_meters:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           n_meters=x)
        print("{}\t: {}".format(".Test n_meters parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_performance_report_parameter(self):
        print("\n----------------------------------------------------------------------")
        performance_report = ["yes", -1]
        for x in performance_report:
            with self.assertRaises(ValueError):
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           performance_report=x)
        print("{}\t: {}".format(".Test performance_report parameter".ljust(60, ' '), colored('OK', 'green')))

    def test_expiration_management(self):
        print("\n----------------------------------------------------------------------")
        # Idle expiration
        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                                         idle_timeout=0)
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        self.assertEqual(last_id, 27)
        # Active expiration
        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                                         active_timeout=0)
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        self.assertEqual(last_id, 27)
        # Custom expiration

        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), udps=FlowSlicer(limit=1))
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        self.assertEqual(last_id, 27)

        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), udps=FlowSlicer(limit=4))
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        self.assertEqual(last_id, 6)

        print("{}\t: {}".format(".Test expiration management".ljust(60, ' '), colored('OK', 'green')))

    def test_tunnel_decoding(self):
        print("\n----------------------------------------------------------------------")
        decode_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "gtp-u.pcap"),
                                     statistical_analysis=True, decode_tunnels=True)
        for flow in decode_streamer:
            self.assertEqual(flow.tunnel_id, 1)
        decode_streamer.decode_tunnels = False
        for flow in decode_streamer:
            self.assertRaises(AttributeError, getattr, flow, "tunnel_id")
        del decode_streamer
        print("{}\t: {}".format(".Test tunnels decoding".ljust(60, ' '), colored('OK', 'green')))

    def test_statistical(self):
        print("\n----------------------------------------------------------------------")
        statistical_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                                          statistical_analysis=True, accounting_mode=1)
        for flow in statistical_streamer:
            self.assertEqual(flow.id, 0)
            self.assertEqual(flow.expiration_id, 0)
            self.assertEqual(flow.src_ip, '172.31.3.224')
            self.assertEqual(flow.src_mac, '80:c6:ca:00:9e:9f')
            self.assertEqual(flow.src_oui, '80:c6:ca')
            self.assertEqual(flow.src_port, 42835)
            self.assertEqual(flow.dst_ip, '216.58.212.100')
            self.assertEqual(flow.dst_mac, '00:0e:8e:4d:b4:a8')
            self.assertEqual(flow.dst_oui, '00:0e:8e')
            self.assertEqual(flow.dst_port, 443)
            self.assertEqual(flow.protocol, 6)
            self.assertEqual(flow.ip_version, 4)
            self.assertEqual(flow.vlan_id, 0)
            self.assertEqual(flow.tunnel_id, 0)
            self.assertEqual(flow.bidirectional_first_seen_ms, 1434443394683)
            self.assertEqual(flow.bidirectional_last_seen_ms, 1434443401353)
            self.assertEqual(flow.bidirectional_duration_ms, 6670)
            self.assertEqual(flow.bidirectional_packets, 28)
            self.assertEqual(flow.bidirectional_bytes, 8696)
            self.assertEqual(flow.src2dst_first_seen_ms, 1434443394683)
            self.assertEqual(flow.src2dst_last_seen_ms, 1434443401353)
            self.assertEqual(flow.src2dst_duration_ms, 6670)
            self.assertEqual(flow.src2dst_packets, 16)
            self.assertEqual(flow.src2dst_bytes, 1288)
            self.assertEqual(flow.dst2src_first_seen_ms, 1434443394717)
            self.assertEqual(flow.dst2src_last_seen_ms, 1434443401308)
            self.assertEqual(flow.dst2src_duration_ms, 6591)
            self.assertEqual(flow.dst2src_packets, 12)
            self.assertEqual(flow.dst2src_bytes, 7408)
            self.assertEqual(flow.bidirectional_min_ps, 40)
            self.assertAlmostEqual(flow.bidirectional_mean_ps, 310.57142857142856)
            self.assertAlmostEqual(flow.bidirectional_stddev_ps, 500.54617788019937)
            self.assertEqual(flow.bidirectional_max_ps, 1470)
            self.assertEqual(flow.src2dst_min_ps, 40)
            self.assertAlmostEqual(flow.src2dst_mean_ps, 80.49999999999999)
            self.assertAlmostEqual(flow.src2dst_stddev_ps, 89.55519713189922)
            self.assertEqual(flow.src2dst_max_ps, 354)
            self.assertEqual(flow.dst2src_min_ps, 40)
            self.assertAlmostEqual(flow.dst2src_mean_ps, 617.3333333333334)
            self.assertAlmostEqual(flow.dst2src_stddev_ps, 651.4524099458397)
            self.assertEqual(flow.dst2src_max_ps, 1470)
            self.assertEqual(flow.bidirectional_min_piat_ms, 0)
            self.assertAlmostEqual(flow.bidirectional_mean_piat_ms, 247.037037037037)
            self.assertAlmostEqual(flow.bidirectional_stddev_piat_ms, 324.04599406227237)
            self.assertEqual(flow.bidirectional_max_piat_ms, 995)
            self.assertEqual(flow.src2dst_min_piat_ms, 76)
            self.assertAlmostEqual(flow.src2dst_mean_piat_ms, 444.6666666666667)
            self.assertAlmostEqual(flow.src2dst_stddev_piat_ms, 397.60329595261277)
            self.assertEqual(flow.src2dst_max_piat_ms, 1185)
            self.assertEqual(flow.dst2src_min_piat_ms, 66)
            self.assertAlmostEqual(flow.dst2src_mean_piat_ms, 599.1818181818182)
            self.assertAlmostEqual(flow.dst2src_stddev_piat_ms, 384.78456782511904)
            self.assertEqual(flow.dst2src_max_piat_ms, 1213)
            self.assertEqual(flow.bidirectional_syn_packets, 2)
            self.assertEqual(flow.bidirectional_cwr_packets, 0)
            self.assertEqual(flow.bidirectional_ece_packets, 0)
            self.assertEqual(flow.bidirectional_urg_packets, 0)
            self.assertEqual(flow.bidirectional_ack_packets, 27)
            self.assertEqual(flow.bidirectional_psh_packets, 8)
            self.assertEqual(flow.bidirectional_rst_packets, 0)
            self.assertEqual(flow.bidirectional_fin_packets, 2)
            self.assertEqual(flow.src2dst_syn_packets, 1)
            self.assertEqual(flow.src2dst_cwr_packets, 0)
            self.assertEqual(flow.src2dst_ece_packets, 0)
            self.assertEqual(flow.src2dst_urg_packets, 0)
            self.assertEqual(flow.src2dst_ack_packets, 15)
            self.assertEqual(flow.src2dst_psh_packets, 4)
            self.assertEqual(flow.src2dst_rst_packets, 0)
            self.assertEqual(flow.src2dst_fin_packets, 1)
            self.assertEqual(flow.dst2src_syn_packets, 1)
            self.assertEqual(flow.dst2src_cwr_packets, 0)
            self.assertEqual(flow.dst2src_ece_packets, 0)
            self.assertEqual(flow.dst2src_urg_packets, 0)
            self.assertEqual(flow.dst2src_ack_packets, 12)
            self.assertEqual(flow.dst2src_psh_packets, 4)
            self.assertEqual(flow.dst2src_rst_packets, 0)
            self.assertEqual(flow.dst2src_fin_packets, 1)
        del statistical_streamer
        print("{}\t: {}".format(".Test statistical extraction".ljust(60, ' '), colored('OK', 'green')))

    def test_fingerprint_extraction(self):
        print("\n----------------------------------------------------------------------")
        fingerprint_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "facebook.pcap"),
                                          statistical_analysis=True, accounting_mode=1)
        for flow in fingerprint_streamer:
            self.assertEqual(flow.application_name, 'TLS.Facebook')
            self.assertEqual(flow.application_category_name, 'SocialNetwork')
            self.assertEqual(flow.application_confidence, 4)
            self.assertTrue(flow.requested_server_name in ['facebook.com', 'www.facebook.com'])
            self.assertTrue(flow.client_fingerprint in ['bfcc1a3891601edb4f137ab7ab25b840',
                                                        '5c60e71f1b8cd40e4d40ed5b6d666e3f'])
            self.assertTrue(flow.server_fingerprint in ['2d1eb5817ece335c24904f516ad5da12',
                                                        '96681175a9547081bf3d417f1a572091'])
        del fingerprint_streamer
        print("{}\t: {}".format(".Test fingerprint extraction".ljust(60, ' '), colored('OK', 'green')))

    def test_export(self):
        print("\n----------------------------------------------------------------------")
        df = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                        statistical_analysis=True, n_dissections=20).to_pandas()
        df_anon = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                             statistical_analysis=True,
                             n_dissections=20).to_pandas(columns_to_anonymize=["src_ip", "dst_ip"])
        self.assertEqual(df_anon.shape[0], df.shape[0])
        self.assertEqual(df_anon.shape[1], df.shape[1])
        self.assertEqual(df_anon['src_ip'].nunique(), df['src_ip'].nunique())
        self.assertEqual(df_anon['dst_ip'].nunique(), df['dst_ip'].nunique())

        total_flows = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                                 statistical_analysis=True, n_dissections=20).to_csv()
        df_from_csv = pd.read_csv(os.path.join("tests", "pcaps", "steam.pcap.csv"))
        total_flows_anon = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                                      statistical_analysis=True, n_dissections=20).to_csv()
        df_anon_from_csv = pd.read_csv(os.path.join("tests", "pcaps", "steam.pcap.csv"))
        os.remove(os.path.join("tests", "pcaps", "steam.pcap.csv"))
        self.assertEqual(total_flows, total_flows_anon)
        self.assertEqual(total_flows, df_from_csv.shape[0])
        self.assertEqual(total_flows_anon, df_anon_from_csv.shape[0])
        self.assertEqual(total_flows, df.shape[0])
        self.assertEqual(total_flows_anon, df_anon.shape[0])
        print("{}\t: {}".format(".Test export interfaces".ljust(60, ' '), colored('OK', 'green')))

    def test_bpf(self):
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source=os.path.join("tests", "pcaps", "facebook.pcap"),
                                   bpf_filter="src port 52066 or dst port 52066")
        last_id = 0
        for flow in streamer_test:
            last_id = flow.id
            self.assertEqual(flow.src_port, 52066)
        self.assertEqual(last_id, 0)
        del streamer_test
        print("{}\t: {}".format(".Test BPF".ljust(60, ' '), colored('OK', 'green')))

    def test_ndpi_integration(self):
        # For Windows platform, the following files from nDPI repository needs further investigations:
        # ocs.pcap
        # quic-mvfst-22_decryption_error.pcap
        # http-crash-content-disposition.pcap
        pcap_files = get_files_list(os.path.join("tests", "pcaps"))
        result_files = get_files_list(os.path.join("tests", "results"))
        failures = 0
        print("\n----------------------------------------------------------------------")
        print(".Test nDPI integration on {} applications:".format(len(pcap_files)))
        for file_idx, test_file in enumerate(pcap_files):
            test_case_name = os.path.basename(test_file)
            try:
                test = NFStreamer(source=test_file,
                                  n_dissections=20,
                                  n_meters=1).to_pandas()[["id",
                                                           "bidirectional_packets",
                                                           "bidirectional_bytes",
                                                           "application_name",
                                                           "application_category_name",
                                                           "application_confidence"]].to_dict()

                true = pd.read_csv(result_files[file_idx]).to_dict()
                self.assertEqual(test, true)
                print("{}\t: {}".format(test_case_name.ljust(60, ' '), colored('OK', 'green')))
            except AssertionError:
                failures += 1
                print("{}\t: {}".format(test_case_name.ljust(60, ' '), colored('KO', 'red')))
                print(" \nExpected:")
                print(true)
                print(" \nObtained:")
                print(test)
        self.assertEqual(failures, 0)

    def test_splt(self):
        print("\n----------------------------------------------------------------------")
        splt_df = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), splt_analysis=5,
                             udps=SPLT(sequence_length=5, accounting_mode=0)).to_pandas()
        direction = json.loads(splt_df["udps.splt_direction"][0])
        ps = json.loads(splt_df["udps.splt_ps"][0])
        piat = json.loads(splt_df["udps.splt_piat_ms"][0])
        ndirection = json.loads(splt_df["splt_direction"][0])
        nps = json.loads(splt_df["splt_ps"][0])
        npiat = json.loads(splt_df["splt_piat_ms"][0])
        self.assertEqual(direction, [0, 1, 0, 0, 1])
        self.assertEqual(ps, [58, 60, 54, 180, 60])
        self.assertEqual(piat, [0, 34, 134, 144, 35])
        self.assertEqual(direction, ndirection)
        self.assertEqual(ps, nps)
        self.assertEqual(piat, npiat)
        print("{}\t: {}".format(".Test SPLT analysis".ljust(60, ' '), colored('OK', 'green')))

    def test_dhcp(self):
        print("\n----------------------------------------------------------------------")
        dhcp_df = NFStreamer(source=os.path.join("tests", "pcaps", "dhcp.pcap"),
                             n_dissections=0,
                             udps=DHCP()
                             ).to_pandas().sort_values(by=['src_ip']).reset_index(drop=True)
        self.assertEqual(dhcp_df["udps.dhcp_msg_type"][0], "MsgType.DISCOVER")
        self.assertEqual(dhcp_df["udps.dhcp_50"][1], "192.168.0.10")
        self.assertEqual(dhcp_df["udps.dhcp_55"][1], "1,3,6,42")
        self.assertEqual(dhcp_df["udps.dhcp_options"][1], "[53, 61, 50, 54, 55]")
        self.assertEqual(dhcp_df["udps.dhcp_msg_type"][1], "MsgType.REQUEST")
        self.assertEqual(dhcp_df["udps.dhcp_oui"][1], "00:0b:82")
        self.assertEqual(dhcp_df.shape[0], 3)
        print("{}\t: {}".format(".Test DHCP plugin".ljust(60, ' '), colored('OK', 'green')))

    def test_mdns(self):
        print("\n----------------------------------------------------------------------")
        mdns_df = NFStreamer(source=os.path.join("tests", "pcaps", "mdns.pcap"),
                             n_dissections=0,
                             udps=MDNS()
                             ).to_pandas().sort_values(by=['src_ip']).reset_index(drop=True)
        self.assertEqual(mdns_df["udps.mdns_ptr"][0], "['skynet.local', "
                                                      "'skynet [00:1a:ef:17:c3:05]._workstation._tcp.local', "
                                                      "'recombinator_mpd._mpd._tcp.local', '_mpd._tcp.local', "
                                                      "'skynet._udisks-ssh._tcp.local', '_udisks-ssh._tcp.local', "
                                                      "'_workstation._tcp.local']")
        print("{}\t: {}".format(".Test MDNS plugin".ljust(60, ' '), colored('OK', 'green')))


if __name__ == '__main__':
    unittest.main()
