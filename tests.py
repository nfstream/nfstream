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


class NFStreamTest(object):
    @staticmethod
    def test_source_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        source = ["inexisting.pcap", "lo", 11]
        for x in source:
            try:
                NFStreamer(source=x).to_pandas()
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 3
        print("{}\t: {}".format(".test_source_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_decode_tunnels_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        decode_tunnels = [33, "True"]
        for x in decode_tunnels:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           decode_tunnels=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_decode_tunnels_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_bpf_filter_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        bpf_filter = ["my filter", 11]
        for x in bpf_filter:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), bpf_filter=x).to_pandas()
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_bpf_filter_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_promiscuous_mode_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        promiscuous_mode = ["yes", 89]
        for x in promiscuous_mode:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), promiscuous_mode=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_promiscuous_mode_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_snapshot_length_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        snapshot_length = ["largest", -1]
        for x in snapshot_length:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), snapshot_length=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_snapshot_length_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_idle_timeout_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        idle_timeout = [-1, "idle"]
        for x in idle_timeout:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), idle_timeout=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_idle_timeout_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_active_timeout_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        active_timeout = [-1, "active"]
        for x in active_timeout:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), active_timeout=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_active_timeout_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_accounting_mode_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        accounting_mode = [-1, 5, 'ip']
        for x in accounting_mode:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), accounting_mode=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 3
        print("{}\t: {}".format(".test_accounting_mode_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_udps_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        udps = [lambda y: y + 1, "NFPlugin"]
        for x in udps:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), udps=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_udps_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_n_dissections_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        n_dissections = ["yes", -1, 256]
        for x in n_dissections:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), n_dissections=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 3
        print("{}\t: {}".format(".test_n_dissections_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_system_visibility_mode_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        system_visibility_mode = ["yes", -1, 3]
        for x in system_visibility_mode:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), system_visibility_mode=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 3
        print("{}\t: {}".format(".test_system_visibility_mode_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_system_visibility_extension_port():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        system_visibility_mode = ["yes", -1, 88888]
        for x in system_visibility_mode:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), system_visibility_extension_port=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 3
        print("{}\t: {}".format(".test_system_visibility_extension_port".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_system_visibility_poll_ms():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        system_visibility_mode = ["yes", -1]
        for x in system_visibility_mode:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), system_visibility_poll_ms=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_system_visibility_poll_ms".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_statistical_analysis_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        statistical_analysis = ["yes", 89]
        for x in statistical_analysis:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), statistical_analysis=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_statistical_analysis_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_splt_analysis_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        splt_analysis = [-1, 256, "yes"]
        for x in splt_analysis:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), splt_analysis=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 3
        print("{}\t: {}".format(".test_splt_analysis_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_n_meters_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        n_meters = ["yes", -1]
        for x in n_meters:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           n_meters=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_n_meters_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_max_nflows_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        max_nflows = ["yes", -1]
        for x in max_nflows:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                           max_nflows=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_max_nflows_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_performance_report_parameter():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        performance_report = ["yes", -1]
        for x in performance_report:
            try:
                NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), performance_report=x)
            except ValueError:
                n_exceptions += 1
        assert n_exceptions == 2
        print("{}\t: {}".format(".test_performance_report_parameter".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_expiration_management():
        print("\n----------------------------------------------------------------------")
        # Idle expiration
        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), idle_timeout=0)
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        assert last_id == 27
        # Active expiration
        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), active_timeout=0)
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        assert last_id == 27
        # Custom expiration
        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                                         udps=FlowSlicer(limit=1))
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        assert last_id == 27
        streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                                         udps=FlowSlicer(limit=4))
        last_id = 0
        for flow in streamer_expiration:
            last_id = flow.id
        assert last_id == 6
        print("{}\t: {}".format(".test_expiration_management".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_tunnel_decoding():
        print("\n----------------------------------------------------------------------")
        n_exceptions = 0
        decode_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "gtp-u.pcap"),
                                     statistical_analysis=True, decode_tunnels=True)
        for flow in decode_streamer:
            assert flow.tunnel_id == 1
        decode_streamer.decode_tunnels = False
        for flow in decode_streamer:
            try:
                getattr(flow, "tunnel_id")
            except AttributeError:
                n_exceptions += 1
        assert n_exceptions == 1
        del decode_streamer
        print("{}\t: {}".format(".test_tunnel_decoding".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_statistical():
        print("\n----------------------------------------------------------------------")
        statistical_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                                          statistical_analysis=True, accounting_mode=1)
        for flow in statistical_streamer:
            assert flow.id == 0
            assert flow.expiration_id == 0
            assert flow.src_ip == '172.31.3.224'
            assert flow.src_mac == '80:c6:ca:00:9e:9f'
            assert flow.src_oui == '80:c6:ca'
            assert flow.src_port == 42835
            assert flow.dst_ip == '216.58.212.100'
            assert flow.dst_mac == '00:0e:8e:4d:b4:a8'
            assert flow.dst_oui == '00:0e:8e'
            assert flow.dst_port == 443
            assert flow.protocol == 6
            assert flow.ip_version == 4
            assert flow.vlan_id == 0
            assert flow.tunnel_id == 0
            assert flow.bidirectional_first_seen_ms == 1434443394683
            assert flow.bidirectional_last_seen_ms == 1434443401353
            assert flow.bidirectional_duration_ms == 6670
            assert flow.bidirectional_packets == 28
            assert flow.bidirectional_bytes == 8696
            assert flow.src2dst_first_seen_ms == 1434443394683
            assert flow.src2dst_last_seen_ms == 1434443401353
            assert flow.src2dst_duration_ms == 6670
            assert flow.src2dst_packets == 16
            assert flow.src2dst_bytes == 1288
            assert flow.dst2src_first_seen_ms == 1434443394717
            assert flow.dst2src_last_seen_ms == 1434443401308
            assert flow.dst2src_duration_ms == 6591
            assert flow.dst2src_packets == 12
            assert flow.dst2src_bytes == 7408
            assert flow.bidirectional_min_ps == 40
            assert (flow.bidirectional_mean_ps - 310.571) < 0.001
            assert (flow.bidirectional_stddev_ps - 500.546) < 0.001
            assert flow.bidirectional_max_ps == 1470
            assert flow.src2dst_min_ps == 40
            assert (flow.src2dst_mean_ps - 80.499) < 0.001
            assert (flow.src2dst_stddev_ps - 89.555) < 0.001
            assert flow.src2dst_max_ps == 354
            assert flow.dst2src_min_ps == 40
            assert (flow.dst2src_mean_ps - 617.333) < 0.001
            assert (flow.dst2src_stddev_ps - 651.452) < 0.001
            assert flow.dst2src_max_ps == 1470
            assert flow.bidirectional_min_piat_ms == 0
            assert (flow.bidirectional_mean_piat_ms - 247.037) < 0.001
            assert (flow.bidirectional_stddev_piat_ms - 324.045) < 0.001
            assert flow.bidirectional_max_piat_ms == 995
            assert flow.src2dst_min_piat_ms == 76
            assert (flow.src2dst_mean_piat_ms - 444.666) < 0.001
            assert (flow.src2dst_stddev_piat_ms - 397.603) < 0.001
            assert flow.src2dst_max_piat_ms == 1185
            assert flow.dst2src_min_piat_ms == 66
            assert (flow.dst2src_mean_piat_ms - 599.181) < 0.001
            assert (flow.dst2src_stddev_piat_ms - 384.784) < 0.001
            assert flow.dst2src_max_piat_ms == 1213
            assert flow.bidirectional_syn_packets == 2
            assert flow.bidirectional_cwr_packets == 0
            assert flow.bidirectional_ece_packets == 0
            assert flow.bidirectional_urg_packets == 0
            assert flow.bidirectional_ack_packets == 27
            assert flow.bidirectional_psh_packets == 8
            assert flow.bidirectional_rst_packets == 0
            assert flow.bidirectional_fin_packets == 2
            assert flow.src2dst_syn_packets == 1
            assert flow.src2dst_cwr_packets == 0
            assert flow.src2dst_ece_packets == 0
            assert flow.src2dst_urg_packets == 0
            assert flow.src2dst_ack_packets == 15
            assert flow.src2dst_psh_packets == 4
            assert flow.src2dst_rst_packets == 0
            assert flow.src2dst_fin_packets == 1
            assert flow.dst2src_syn_packets == 1
            assert flow.dst2src_cwr_packets == 0
            assert flow.dst2src_ece_packets == 0
            assert flow.dst2src_urg_packets == 0
            assert flow.dst2src_ack_packets == 12
            assert flow.dst2src_psh_packets == 4
            assert flow.dst2src_rst_packets == 0
            assert flow.dst2src_fin_packets == 1
            del statistical_streamer
        print("{}\t: {}".format(".test_statistical".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_fingerprint_extraction():
        print("\n----------------------------------------------------------------------")
        fingerprint_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "facebook.pcap"),
                                          statistical_analysis=True, accounting_mode=1)
        for flow in fingerprint_streamer:
            assert flow.application_name == 'TLS.Facebook'
            assert flow.application_category_name == 'SocialNetwork'
            assert flow.application_is_guessed == 0
            assert flow.application_confidence == 210
            requested_server_name = flow.requested_server_name in ['facebook.com', 'www.facebook.com']
            assert int(requested_server_name) == 1
            client_fingerprint = flow.client_fingerprint in ['bfcc1a3891601edb4f137ab7ab25b840',
                                                             '5c60e71f1b8cd40e4d40ed5b6d666e3f']
            assert int(client_fingerprint) == 1
            server_fingerprint = flow.server_fingerprint in ['2d1eb5817ece335c24904f516ad5da12',
                                                             '96681175a9547081bf3d417f1a572091']
            assert int(server_fingerprint) == 1
        del fingerprint_streamer
        print("{}\t: {}".format(".test_fingerprint_extraction".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_export():
        print("\n----------------------------------------------------------------------")
        df = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                        statistical_analysis=True, n_dissections=20).to_pandas()
        df_anon = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                             statistical_analysis=True,
                             n_dissections=20).to_pandas(columns_to_anonymize=["src_ip", "dst_ip"])
        assert df_anon.shape[0] == df.shape[0]
        assert df_anon.shape[1] == df.shape[1]
        assert df_anon['src_ip'].nunique() == df['src_ip'].nunique()
        assert df_anon['dst_ip'].nunique() == df['dst_ip'].nunique()
        total_flows = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                                 statistical_analysis=True, n_dissections=20).to_csv()
        df_from_csv = pd.read_csv(os.path.join("tests", "pcaps", "steam.pcap.csv"))
        total_flows_anon = NFStreamer(source=os.path.join("tests", "pcaps", "steam.pcap"),
                                      statistical_analysis=True, n_dissections=20).to_csv()
        df_anon_from_csv = pd.read_csv(os.path.join("tests", "pcaps", "steam.pcap.csv"))
        os.remove(os.path.join("tests", "pcaps", "steam.pcap.csv"))
        assert total_flows == total_flows_anon
        assert total_flows == df_from_csv.shape[0]
        assert total_flows_anon == df_anon_from_csv.shape[0]
        assert total_flows == df.shape[0]
        assert total_flows_anon == df_anon.shape[0]
        print("{}\t: {}".format(".test_export".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_bpf():
        print("\n----------------------------------------------------------------------")
        streamer_test = NFStreamer(source=os.path.join("tests", "pcaps", "facebook.pcap"),
                                   bpf_filter="src port 52066 or dst port 52066")
        last_id = 0
        for flow in streamer_test:
            last_id = flow.id
            assert flow.src_port == 52066
        assert last_id == 0
        print("{}\t: {}".format(".test_bpf".ljust(60, ' '), colored('OK', 'green')))


    @staticmethod
    def test_ndpi_integration():
        print("\n----------------------------------------------------------------------")
        pcap_files = get_files_list(os.path.join("tests", "pcaps"))
        result_files = get_files_list(os.path.join("tests", "results"))
        failures = 0
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
                                                           "application_is_guessed",
                                                           "application_confidence"]].to_dict()

                true = pd.read_csv(result_files[file_idx]).to_dict()
                assert test == true
                print("{}\t: {}".format(test_case_name.ljust(60, ' '), colored('OK', 'green')))
            except AssertionError:
                failures += 1
                print("{}\t: {}".format(test_case_name.ljust(60, ' '), colored('KO', 'red')))
        # Everything must be OK
        assert failures == 0

    @staticmethod
    def test_splt():
        print("\n----------------------------------------------------------------------")
        splt_df = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), splt_analysis=5,
                             udps=SPLT(sequence_length=5, accounting_mode=0)).to_pandas()
        direction = json.loads(splt_df["udps.splt_direction"][0])
        ps = json.loads(splt_df["udps.splt_ps"][0])
        piat = json.loads(splt_df["udps.splt_piat_ms"][0])
        ndirection = json.loads(splt_df["splt_direction"][0])
        nps = json.loads(splt_df["splt_ps"][0])
        npiat = json.loads(splt_df["splt_piat_ms"][0])
        assert direction == [0, 1, 0, 0, 1]
        assert ps == [58, 60, 54, 180, 60]
        assert piat == [0, 34, 134, 144, 35]
        assert direction == ndirection
        assert ps == nps
        assert piat == npiat
        print("{}\t: {}".format(".test_splt".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_dhcp():
        print("\n----------------------------------------------------------------------")
        dhcp_df = NFStreamer(source=os.path.join("tests", "pcaps", "dhcp.pcap"), n_dissections=0, udps=DHCP()) \
            .to_pandas().sort_values(by=['src_ip']).reset_index(drop=True)
        assert dhcp_df["udps.dhcp_msg_type"][0] == "MsgType.DISCOVER"
        assert dhcp_df["udps.dhcp_50"][1] == "192.168.0.10"
        assert dhcp_df["udps.dhcp_55"][1] == "1,3,6,42"
        assert dhcp_df["udps.dhcp_options"][1] == "[53, 61, 50, 54, 55]"
        assert dhcp_df["udps.dhcp_msg_type"][1] == "MsgType.REQUEST"
        assert dhcp_df["udps.dhcp_oui"][1] == "00:0b:82"
        assert dhcp_df.shape[0] == 3
        print("{}\t: {}".format(".test_dhcp".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_mdns():
        print("\n----------------------------------------------------------------------")
        mdns_df = NFStreamer(source=os.path.join("tests", "pcaps", "mdns.pcap"), n_dissections=0, udps=MDNS()) \
            .to_pandas().sort_values(by=['src_ip']).reset_index(drop=True)
        assert mdns_df["udps.mdns_ptr"][0] == "['skynet.local', " \
                                              "'skynet [00:1a:ef:17:c3:05]._workstation._tcp.local', " \
                                              "'recombinator_mpd._mpd._tcp.local', '_mpd._tcp.local', " \
                                              "'skynet._udisks-ssh._tcp.local', '_udisks-ssh._tcp.local', " \
                                              "'_workstation._tcp.local']"
        print("{}\t: {}".format(".test_mdns".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_multi_files():
        print("\n----------------------------------------------------------------------")
        multi_files = [os.path.join("tests", "pcaps", "one_flow_1_5.pcap"),
                       os.path.join("tests", "pcaps", "one_flow_6_10.pcap"),
                       os.path.join("tests", "pcaps", "one_flow_11_15.pcap"),
                       os.path.join("tests", "pcaps", "one_flow_16_19.pcap")]
        for flow in NFStreamer(source=multi_files):
            assert flow.id == 0
            assert flow.expiration_id == 0
            assert flow.src_ip == "192.168.43.18"
            assert flow.src_mac == "30:52:cb:6c:9c:1b"
            assert flow.src_oui == "30:52:cb"
            assert flow.src_port == 52066
            assert flow.dst_ip == "66.220.156.68"
            assert flow.dst_mac == "98:0c:82:d3:3c:7c"
            assert flow.dst_oui == "98:0c:82"
            assert flow.dst_port == 443
            assert flow.protocol == 6
            assert flow.ip_version == 4
            assert flow.vlan_id == 0
            assert flow.tunnel_id == 0
            assert flow.bidirectional_first_seen_ms == 1472393122365
            assert flow.bidirectional_last_seen_ms == 1472393123665
            assert flow.bidirectional_duration_ms == 1300
            assert flow.bidirectional_packets == 19
            assert flow.bidirectional_bytes == 5745
            assert flow.src2dst_first_seen_ms == 1472393122365
            assert flow.src2dst_last_seen_ms == 1472393123408
            assert flow.src2dst_duration_ms == 1043
            assert flow.src2dst_packets == 9
            assert flow.src2dst_bytes == 1345
            assert flow.dst2src_first_seen_ms == 1472393122668
            assert flow.dst2src_last_seen_ms == 1472393123665
            assert flow.dst2src_duration_ms == 997
            assert flow.dst2src_packets == 10
            assert flow.dst2src_bytes == 4400
            assert flow.application_name == "TLS.Facebook"
            assert flow.application_category_name == "SocialNetwork"
            assert flow.application_is_guessed == 0
            assert flow.application_confidence == 210
            assert flow.requested_server_name == "facebook.com"
            assert flow.client_fingerprint == "bfcc1a3891601edb4f137ab7ab25b840"
            assert flow.server_fingerprint == "2d1eb5817ece335c24904f516ad5da12"
            assert flow.user_agent == ""
            assert flow.content_type == ""
        print("{}\t: {}".format(".test_multi_files".ljust(60, ' '), colored('OK', 'green')))

    @staticmethod
    def test_max_nflows():
        print("\n----------------------------------------------------------------------")
        df = NFStreamer(source=os.path.join("tests", "pcaps", "skype.pcap")).to_pandas()
        assert df.shape[0] == 294
        df = NFStreamer(source=os.path.join("tests", "pcaps", "skype.pcap"), max_nflows=100).to_pandas()
        assert df.shape[0] == 100
        df = NFStreamer(source=os.path.join("tests", "pcaps", "skype.pcap"), max_nflows=0).to_pandas()
        assert df.shape[0] == 294
        print("{}\t: {}".format(".test_max_nflows".ljust(60, ' '), colored('OK', 'green')))


if __name__ == '__main__':
    NFStreamTest.test_source_parameter()
    NFStreamTest.test_decode_tunnels_parameter()
    NFStreamTest.test_bpf_filter_parameter()
    NFStreamTest.test_promiscuous_mode_parameter()
    NFStreamTest.test_snapshot_length_parameter()
    NFStreamTest.test_idle_timeout_parameter()
    NFStreamTest.test_active_timeout_parameter()
    NFStreamTest.test_accounting_mode_parameter()
    NFStreamTest.test_udps_parameter()
    NFStreamTest.test_n_dissections_parameter()
    NFStreamTest.test_system_visibility_mode_parameter()
    NFStreamTest.test_system_visibility_extension_port()
    NFStreamTest.test_system_visibility_poll_ms()
    NFStreamTest.test_statistical_analysis_parameter()
    NFStreamTest.test_splt_analysis_parameter()
    NFStreamTest.test_n_meters_parameter()
    NFStreamTest.test_max_nflows_parameter()
    NFStreamTest.test_performance_report_parameter()
    NFStreamTest.test_expiration_management()
    NFStreamTest.test_tunnel_decoding()
    NFStreamTest.test_statistical()
    NFStreamTest.test_fingerprint_extraction()
    NFStreamTest.test_export()
    NFStreamTest.test_bpf()
    NFStreamTest.test_ndpi_integration()
    NFStreamTest.test_splt()
    NFStreamTest.test_dhcp()
    NFStreamTest.test_mdns()
    NFStreamTest.test_multi_files()
    NFStreamTest.test_max_nflows()
