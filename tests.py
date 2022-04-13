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

from nfstream.plugins import SPLT, DHCP, FlowSlicer, MDNS
from nfstream import NFStreamer
import pandas as pd
import pytest
import json
import os


def get_files_list(path):
    files = []
    for r, d, f in os.walk(path):
        for file in f:
            if '.pcap' == file[-5:] or ".pcapng" == file[-7:]:  # Pick out only pcaps files
                files.append(os.path.join(r, file))
    files.sort()
    return files


def test_source_parameter():
    source = ["inexisting.pcap", "lo", 11]
    for x in source:
        with pytest.raises(ValueError):
            NFStreamer(source=x).to_pandas()


def test_decode_tunnels_parameter():
    decode_tunnels = [33, "True"]
    for x in decode_tunnels:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                       decode_tunnels=x)


def test_bpf_filter_parameter():
    bpf_filter = ["my filter", 11]
    for x in bpf_filter:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), bpf_filter=x).to_pandas()


def test_promiscuous_mode_parameter():
    promiscuous_mode = ["yes", 89]
    for x in promiscuous_mode:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), promiscuous_mode=x)


def test_snapshot_length_parameter():
    snapshot_length = ["largest", -1]
    for x in snapshot_length:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), snapshot_length=x)


def test_idle_timeout_parameter():
    idle_timeout = [-1, "idle"]
    for x in idle_timeout:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), idle_timeout=x)


def test_active_timeout_parameter():
    active_timeout = [-1, "active"]
    for x in active_timeout:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), active_timeout=x)


def test_accounting_mode_parameter():
    print("\n----------------------------------------------------------------------")
    accounting_mode = [-1, 5, 'ip']
    for x in accounting_mode:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), accounting_mode=x)


def test_udps_parameter():
    udps = [lambda y: y+1, "NFPlugin"]
    for x in udps:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), udps=x)


def test_n_dissections_parameter():
    n_dissections = ["yes", -1, 256]
    for x in n_dissections:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), n_dissections=x)


def test_system_visibility_mode_parameter():
    system_visibility_mode = ["yes", -1, 3]
    for x in system_visibility_mode:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), system_visibility_mode=x)


def test_system_visibility_extension_port():
    system_visibility_mode = ["yes", -1, 88888]
    for x in system_visibility_mode:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), system_visibility_extension_port=x)


def test_system_visibility_poll_ms():
    system_visibility_mode = ["yes", -1]
    for x in system_visibility_mode:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), system_visibility_poll_ms=x)


def test_statistical_analysis_parameter():
    statistical_analysis = ["yes", 89]
    for x in statistical_analysis:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), statistical_analysis=x)


def test_splt_analysis_parameter():
    splt_analysis = [-1, 256, "yes"]
    for x in splt_analysis:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), splt_analysis=x)


def test_n_meters_parameter():
    n_meters = ["yes", -1]
    for x in n_meters:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"),
                       n_meters=x)


def test_performance_report_parameter():
    performance_report = ["yes", -1]
    for x in performance_report:
        with pytest.raises(ValueError):
            NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), performance_report=x)


def test_expiration_management():
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
    streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), udps=FlowSlicer(limit=1))
    last_id = 0
    for flow in streamer_expiration:
        last_id = flow.id
    assert last_id == 27
    streamer_expiration = NFStreamer(source=os.path.join("tests", "pcaps", "google_ssl.pcap"), udps=FlowSlicer(limit=4))
    last_id = 0
    for flow in streamer_expiration:
        last_id = flow.id
    assert last_id == 6


def test_tunnel_decoding():
    decode_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "gtp-u.pcap"),
                                 statistical_analysis=True, decode_tunnels=True)
    for flow in decode_streamer:
        assert flow.tunnel_id == 1
    decode_streamer.decode_tunnels = False
    for flow in decode_streamer:
        with pytest.raises(AttributeError):
            getattr(flow, "tunnel_id")
    del decode_streamer


def test_statistical():
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
        assert flow.bidirectional_mean_ps == pytest.approx(310.571, 0.001)
        assert flow.bidirectional_stddev_ps == pytest.approx(500.546, 0.001)
        assert flow.bidirectional_max_ps == 1470
        assert flow.src2dst_min_ps == 40
        assert flow.src2dst_mean_ps == pytest.approx(80.499, 0.001)
        assert flow.src2dst_stddev_ps == pytest.approx(89.555, 0.001)
        assert flow.src2dst_max_ps == 354
        assert flow.dst2src_min_ps == 40
        assert flow.dst2src_mean_ps == pytest.approx(617.333, 0.001)
        assert flow.dst2src_stddev_ps == pytest.approx(651.452, 0.001)
        assert flow.dst2src_max_ps == 1470
        assert flow.bidirectional_min_piat_ms == 0
        assert flow.bidirectional_mean_piat_ms == pytest.approx(247.037, 0.001)
        assert flow.bidirectional_stddev_piat_ms == pytest.approx(324.045, 0.001)
        assert flow.bidirectional_max_piat_ms == 995
        assert flow.src2dst_min_piat_ms == 76
        assert flow.src2dst_mean_piat_ms == pytest.approx(444.666, 0.001)
        assert flow.src2dst_stddev_piat_ms == pytest.approx(397.603, 0.001)
        assert flow.src2dst_max_piat_ms == 1185
        assert flow.dst2src_min_piat_ms == 66
        assert flow.dst2src_mean_piat_ms == pytest.approx(599.181, 0.001)
        assert flow.dst2src_stddev_piat_ms == pytest.approx(384.784, 0.001)
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


def test_fingerprint_extraction():
    fingerprint_streamer = NFStreamer(source=os.path.join("tests", "pcaps", "facebook.pcap"),
                                      statistical_analysis=True, accounting_mode=1)
    for flow in fingerprint_streamer:
        assert flow.application_name == 'TLS.Facebook'
        assert flow.application_category_name == 'SocialNetwork'
        assert flow.application_is_guessed == 0
        assert flow.application_confidence == 4
        requested_server_name = flow.requested_server_name in ['facebook.com', 'www.facebook.com']
        assert int(requested_server_name) == 1
        client_fingerprint = flow.client_fingerprint in ['bfcc1a3891601edb4f137ab7ab25b840',
                                                         '5c60e71f1b8cd40e4d40ed5b6d666e3f']
        assert int(client_fingerprint) == 1
        server_fingerprint = flow.server_fingerprint in ['2d1eb5817ece335c24904f516ad5da12',
                                                         '96681175a9547081bf3d417f1a572091']
        assert int(server_fingerprint) == 1
    del fingerprint_streamer


def test_export():
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


def test_bpf():
    streamer_test = NFStreamer(source=os.path.join("tests", "pcaps", "facebook.pcap"),
                               bpf_filter="src port 52066 or dst port 52066")
    last_id = 0
    for flow in streamer_test:
        last_id = flow.id
        assert flow.src_port == 52066
    assert last_id == 0


def test_ndpi_integration():
    # For Windows platform, we have result mismatch on a subset of files
    # We ignore these errors as Windows support is WIP in nDPI project:
    # MR: https://github.com/ntop/nDPI/pull/1491
    pcap_files = get_files_list(os.path.join("tests", "pcaps"))
    result_files = get_files_list(os.path.join("tests", "results"))
    failures = 0
    for file_idx, test_file in enumerate(pcap_files):
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
        except AssertionError:
            failures += 1
    if os.name != 'posix':  # FIXME once nDPI Windows support is finalized.
        assert failures == 8
    else:  # Everything must be OK
        assert failures == 0


def test_splt():
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


def test_dhcp():
    dhcp_df = NFStreamer(source=os.path.join("tests", "pcaps", "dhcp.pcap"), n_dissections=0, udps=DHCP())\
        .to_pandas().sort_values(by=['src_ip']).reset_index(drop=True)
    assert dhcp_df["udps.dhcp_msg_type"][0] == "MsgType.DISCOVER"
    assert dhcp_df["udps.dhcp_50"][1] == "192.168.0.10"
    assert dhcp_df["udps.dhcp_55"][1] == "1,3,6,42"
    assert dhcp_df["udps.dhcp_options"][1] == "[53, 61, 50, 54, 55]"
    assert dhcp_df["udps.dhcp_msg_type"][1] == "MsgType.REQUEST"
    assert dhcp_df["udps.dhcp_oui"][1] == "00:0b:82"
    assert dhcp_df.shape[0] == 3


def test_mdns():
    mdns_df = NFStreamer(source=os.path.join("tests", "pcaps", "mdns.pcap"), n_dissections=0, udps=MDNS())\
        .to_pandas().sort_values(by=['src_ip']).reset_index(drop=True)
    assert mdns_df["udps.mdns_ptr"][0] == "['skynet.local', "\
                                          "'skynet [00:1a:ef:17:c3:05]._workstation._tcp.local', "\
                                          "'recombinator_mpd._mpd._tcp.local', '_mpd._tcp.local', "\
                                          "'skynet._udisks-ssh._tcp.local', '_udisks-ssh._tcp.local', "\
                                          "'_workstation._tcp.local']"
