#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: tests.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

import unittest
from nfstream import NFStreamer
import os


ground_truth_ndpi = {'pps.pcap': {'HTTP': 1849543, 'HTTP.Google': 1093, 'SSDP': 17143},
                     'dropbox.pcap': {'DNS.Dropbox': 4522, 'Dropbox': 86010},
                     'nintendo.pcap': {'Amazon': 2216, 'DNS.Nintendo': 1550, 'ICMP': 2100, 'Nintendo': 303230,
                                       'TLS.Amazon': 8595, 'TLS.Nintendo': 15462},
                     'BGP_redist.pcap': {'BGP': 322},
                     'ssdp-m-search.pcap': {'SSDP': 1197},
                     'ssh.pcap': {'SSH': 35546},
                     'rx.pcap': {'RX': 26475},
                     'whatsapp_login_call.pcap': {'ApplePush': 5926, 'DHCP': 3420, 'DNS.Apple': 330,
                                                  'DNS.WhatsApp': 280, 'Dropbox': 2176, 'HTTP': 726,
                                                  'ICMP': 700, 'IMAPS.Apple': 1998, 'MDNS': 952,
                                                  'STUN.WhatsAppCall': 102942, 'Spotify': 258,
                                                  'TLS': 589, 'TLS.Apple': 47935, 'WhatsApp': 24874},
                     'bittorrent.pcap': {'BitTorrent': 305728},
                     'tor.pcap': {'DHCPV6': 906, 'Dropbox': 1860, 'NetBIOS': 252, 'TLS': 60, 'Tor': 3014362},
                     'mpegts.pcap': {'MPEG_TS': 1362},
                     'steam.pcap': {'Steam': 9020},
                     '6in4tunnel.pcap': {'DNS.Facebook': 800, 'HTTP': 1792, 'ICMPV6': 7862, 'IMAPS': 516,
                                         'TLS': 15397, 'TLS.Facebook': 13926}, 'fix.pcap': {'FIX': 115514},
                     'anyconnect-vpn.pcap': {'AJP': 390, 'ApplePush': 359, 'CiscoVPN': 4378, 'DNS': 3655,
                                             'DNS.Apple': 297, 'DNS.ApplePush': 966, 'DNS.Slack': 154, 'HTTP': 11137,
                                             'ICMP': 126, 'ICMPV6': 2964, 'IGMP': 378, 'MDNS': 4279, 'NetBIOS': 1542,
                                             'SSDP': 5625, 'TLS': 78703, 'TLS.Amazon': 3540, 'TLS.Google': 132,
                                             'TLS.Slack': 4825},
                     'bittorrent_utp.pcap': {'BitTorrent': 41489},
                     'skype_no_unknown.pcap': {'ApplePush': 1118, 'DNS': 267, 'DNS.Skype': 11566, 'Dropbox': 4352,
                                               'ICMP': 328, 'IGMP': 226, 'MDNS': 400, 'NetBIOS': 3106, 'SSDP': 14100,
                                               'Skype': 113238, 'Skype.SkypeCall': 10918, 'TLS': 7742,
                                               'TLS.Apple': 19581, 'TLS.Dropbox': 2990, 'TLS.MS_OneDrive': 181687,
                                               'TLS.Skype': 25336},
                     'youtubeupload.pcap': {'QUIC.YouTubeUpload': 121590, 'TLS.YouTubeUpload': 5448},
                     'ftp.pcap': {'FTP_CONTROL': 5571, 'FTP_DATA': 1819},
                     'ethereum.pcap': {'Mining': 134165},
                     'bt_search.pcap': {'BitTorrent': 322},
                     'viber.pcap': {'DNS': 1267, 'DNS.Facebook': 281, 'DNS.Google': 164, 'DNS.Viber': 527,
                                    'ICMP': 3028, 'ICMPV6': 140, 'MDNS': 412, 'QUIC.Google': 194,
                                    'TLS': 8597, 'TLS.Amazon': 24849, 'TLS.Google': 8775, 'TLS.Viber': 75823,
                                    'Viber': 23174},
                     'NTPv2.pcap': {'NTP': 410},
                     'drda_db2.pcap': {'DRDA': 6691},
                     'google_ssl.pcap': {'TLS.Google': 9108},
                     'whatsapp_voice_and_message.pcap': {'STUN.WhatsAppCall': 5916, 'WhatsApp': 22139},
                     'modbus.pcap': {'Modbus': 6681},
                     'webex.pcap': {'HTTP': 3182, 'SIP': 15356, 'TLS': 11841, 'TLS.Amazon': 9742, 'TLS.Google': 6375,
                                    'TLS.Webex': 817236, 'Webex': 1171},
                     'instagram.pcap': {'DNS.Instagram': 1075, 'Dropbox': 725, 'HTTP': 91784, 'HTTP.Facebook': 153558,
                                        'HTTP.Instagram': 224529, 'ICMP': 510, 'TLS': 169, 'TLS.Facebook': 62428,
                                        'TLS.Instagram': 29490}, 'sip.pcap': {'RTCP': 146, 'RTP': 1926, 'SIP': 47087},
                     'teredo.pcap': {'Teredo': 2574},
                     'whatsapp_login_chat.pcap': {'ApplePush': 2095, 'DHCP': 2052, 'DNS.WhatsApp': 280, 'Dropbox': 1088,
                                                  'MDNS': 202, 'Spotify': 86, 'TLS.Apple': 21371, 'WhatsApp': 2963},
                     'openvpn.pcap': {'OpenVPN': 57111},
                     'Oscar.pcap': {'Oscar': 9386},
                     'upnp.pcap': {'UPnP': 9912},
                     'msnms.pcap': {'MSN': 56503},
                     'coap_mqtt.pcap': {'COAP': 1614, 'Dropbox': 80676, 'MQTT': 668291},
                     'monero.pcap': {'Mining': 166676},
                     'wireguard.pcap': {'WireGuard': 734182},
                     'malware.pcap': {'DNS': 216, 'HTTP': 547, 'ICMP': 98, 'TLS.OpenDNS': 7140},
                     'nest_log_sink.pcap': {'DNS': 1612, 'NestLogSink': 116848},
                     'http_ipv6.pcap': {'QUIC': 502, 'QUIC.Google': 15977, 'TLS': 3245, 'TLS.Facebook': 10202,
                                        'TLS.ntop': 36401},
                     'netflix.pcap': {'DNS': 386, 'DNS.NetFlix': 4083, 'HTTP.NetFlix': 5544013, 'IGMP': 60,
                                      'SSDP': 2648, 'TLS.Amazon': 126, 'TLS.NetFlix': 603725},
                     'smbv1.pcap': {'SMBv1': 1197},
                     'ocs.pcap': {'DNS.Google': 214, 'DNS.GoogleServices': 65, 'DNS.OCS': 180, 'DNS.PlayStore': 72,
                                  'Google': 120, 'HTTP': 1019, 'HTTP.OCS': 51283, 'TLS.Amazon': 2715,
                                  'TLS.Google': 3056, 'TLS.GoogleServices': 2212, 'TLS.OCS': 6089},
                     'NTPv4.pcap': {'NTP': 90},
                     'whatsappfiles.pcap': {'TLS.WhatsAppFiles': 452233},
                     'youtube_quic.pcap': {'QUIC.Google': 13144, 'QUIC.YouTube': 178495},
                     'waze.pcap': {'HTTP': 64777, 'HTTP.Waze': 11962, 'NTP': 180, 'TLS': 432, 'TLS.Google': 2142,
                                   'TLS.Waze': 277373, 'WhatsApp': 1341},
                     'git.pcap': {'Git': 74005},
                     'facebook.pcap': {'TLS.Facebook': 30511},
                     'signal.pcap': {'DHCP': 1368, 'DNS': 186, 'DNS.Signal': 290, 'ICMP': 70, 'TLS': 1417,
                                     'TLS.Apple': 605, 'TLS.AppleiTunes': 29795, 'TLS.Signal': 282037},
                     'dnscrypt.pcap': {'TLS': 44676},
                     'rdp.pcap': {'RDP': 622743},
                     'mssql_tds.pcap': {'MsSQL-TDS': 16260},
                     'quic.pcap': {'QUIC.GMail': 254874, 'QUIC.Google': 10427, 'QUIC.YouTube': 76193},
                     'amqp.pcap': {'AMQP': 23514},
                     'NTPv3.pcap': {'NTP': 90},
                     'mpeg.pcap': {'HTTP.ntop': 10643},
                     'KakaoTalk_chat.pcap': {'Amazon': 181, 'DNS': 217, 'DNS.Facebook': 643, 'DNS.KakaoTalk': 2864,
                                             'Google': 164, 'HTTP': 56, 'HTTP.Facebook': 2172, 'HTTP.Google': 784,
                                             'HTTP_Proxy': 3926, 'ICMP': 147, 'TLS': 2689, 'TLS.Amazon': 1890,
                                             'TLS.Facebook': 48994, 'TLS.Google': 83, 'TLS.KakaoTalk': 7126},
                     'diameter.pcap': {'Diameter': 1980},
                     '1kxun.pcap': {'DHCP': 8208, 'DHCPV6': 980, 'DNS': 638, 'DNS.Google': 815, 'DNS.QQ': 266,
                                    'HTTP': 530967, 'HTTP.Google': 176, 'HTTP.QQ': 4950, 'LLMNR': 6799,
                                    'MDNS': 82, 'NTP': 90, 'NetBIOS': 3589, 'RTP': 132, 'SSDP': 36951, 'STUN': 340,
                                    'TLS': 21914, 'TLS.Facebook': 6840},
                     'vnc.pcap': {'VNC': 329158},
                     'ookla.pcap': {'Ookla': 4689745},
                     'skype-conference-call.pcap': {'STUN.SkypeCall': 39687},
                     'smpp_in_general.pcap': {'SMPP': 1144},
                     'bittorrent_ip.pcap': {'BitTorrent': 508018},
                     'wechat.pcap': {'DHCP': 342, 'DNS': 494, 'DNS.Google': 1296, 'DNS.GoogleDocs': 302, 'DNS.QQ': 610,
                                     'DNS.WeChat': 1383, 'Google': 1320, 'HTTP': 4620, 'ICMPV6': 328, 'IGMP': 1280,
                                     'LLMNR': 944, 'MDNS': 10672, 'NTP': 90, 'NetBIOS': 1579,
                                     'QUIC.Google': 10808, 'QUIC.GoogleDocs': 4812, 'TLS': 1209, 'TLS.Google': 11387,
                                     'TLS.QQ': 8792, 'TLS.WeChat': 605042},
                     'check_mk_new.pcap': {'CHECKMK': 20242},
                     'skype.pcap': {'ApplePush': 1877, 'DNS': 267, 'DNS.AppleiCloud': 234, 'DNS.Skype': 15864,
                                    'Dropbox': 11968, 'ICMP': 656, 'IGMP': 258, 'MDNS': 1736, 'NTP': 180,
                                    'SSDP': 38156, 'Skype': 198600, 'Skype.SkypeCall': 10704, 'Spotify': 430,
                                    'TLS': 8876, 'TLS.Apple': 168, 'TLS.AppleiCloud': 20286, 'TLS.Dropbox': 5980,
                                    'TLS.MS_OneDrive': 198090, 'TLS.Skype': 38567},
                     'tinc.pcap': {'TINC': 352291},
                     'hangout.pcap': {'STUN.GoogleHangoutDuo': 2774},
                     'ps_vue.pcap': {'HTTP.PS_VUE': 2198169, 'TLS': 1401, 'TLS.Amazon': 1380},
                     'quickplay.pcap': {'HTTP': 96179, 'HTTP.Amazon': 1469, 'HTTP.Facebook': 1740,
                                        'HTTP.Google': 378, 'HTTP.QQ': 4781},
                     'EAQ.pcap': {'EAQ': 10092, 'HTTP.Google': 11743},
                     'ubntac2.pcap': {'UBNTAC2': 1736},
                     'zcash.pcap': {'Mining': 20644},
                     'BGP_Cisco_hdlc_slarp.pcap': {'BGP': 969},
                     'bitcoin.pcap': {'Mining': 581074},
                     'weibo.pcap': {'DNS': 1059, 'DNS.Sina(Weibo)': 1206, 'HTTP': 2275, 'HTTP.Sina(Weibo)': 256871,
                                    'QUIC.Google': 4118, 'TLS': 1234, 'TLS.Amazon': 132, 'TLS.Google': 660},
                     'starcraft_battle.pcap': {'DNS': 2848, 'Google': 121, 'HTTP': 294880, 'HTTP.Google': 1299,
                                               'HTTP.WorldOfWarcraft': 880, 'IGMP': 120, 'QUIC.Google': 475,
                                               'SSDP': 4984, 'Starcraft': 51494, 'TLS': 2548, 'TLS.Github': 234,
                                               'TLS.Google': 289},
                     'KakaoTalk_talk.pcap': {'Amazon': 396, 'DNS.Facebook': 197, 'Google': 164, 'HTTP': 280,
                                             'HTTP.QQ': 1727, 'HTTP_Proxy': 1838, 'KakaoTalk_Voice': 6196,
                                             'RTP': 398751, 'TLS': 21844, 'TLS.Facebook': 4204, 'TLS.Google': 195},
                     'zoom.pcap': {'DHCP': 321, 'DNS': 205, 'DNS.Zoom': 838, 'HTTP.Google': 952, 'ICMP': 210,
                                   'IMAPS': 226, 'MDNS': 87, 'NetBIOS': 330, 'SSDP': 168, 'STUN.Zoom': 1440,
                                   'Spotify': 86, 'TLS': 114, 'TLS.Google': 7899, 'TLS.Zoom': 158195,
                                   'TLS.ntop': 4265, 'Zoom': 193532},
                     'snapchat.pcap': {'TLS.Google': 2879, 'TLS.Snapchat': 7320},
                     'netflowv9.pcap': {'NetFlow': 13888}
                     }


def get_files_list(path):
    files = []
    for r, d, f in os.walk(path):
        for file in f:
            files.append(os.path.join(r, file))
    return files


class TestMethods(unittest.TestCase):
    def test_no_unknown_protocols_without_timeouts(self):
        files = get_files_list("tests/")
        self.maxDif = None
        print("----------------------------------------------------------------------")
        print(".Testing on {} applications:".format(len(files)))
        for file in files:
            streamer_test = NFStreamer(source=file)
            test_case_name = file.split('/')[-1]
            print(test_case_name)
            result = {}
            for flow in streamer_test:
                if flow.application_name != 'Unknown':
                    try:
                        result[flow.application_name] += flow.total_bytes
                    except KeyError:
                        result[flow.application_name] = flow.total_bytes
            self.assertEqual(result, ground_truth_ndpi[test_case_name])
            print('PASS.')

    def test_expiration_management(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing Streamer expiration management:")
        streamer_test = NFStreamer(source='tests/facebook.pcap', active_timeout=0)
        flows = []
        for flow in streamer_test:
            flows.append(flow)
        self.assertEqual(len(flows), 60)
        print('PASS.')

    def test_flow_str_representation(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing Flow string representation:")
        streamer_test = NFStreamer(source='tests/facebook.pcap')
        flows = list(streamer_test)
        del streamer_test
        print(flows[0])
        print('PASS.')

    def test_unfound_device(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing unfoud device")
        try:
            streamer_test = NFStreamer(source="inexisting_file.pcap")
        except SystemExit:
            print("PASS.")

    def test_bpf_filter(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing bpf filtering:")
        bpf_filter = "tcp src port 44614"
        streamer_test = NFStreamer(source='tests/facebook.pcap', bpf_filter=bpf_filter)
        flows = list(streamer_test)
        print(flows[0])
        self.assertEqual(len(flows), 1)
        print('PASS.')


if __name__ == '__main__':
    unittest.main()