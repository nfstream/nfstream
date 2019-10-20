import unittest
from nfstream.streamer import Streamer, FlowKey
from colorama import Fore, Style
import os
import json

def get_files_list(path):
    files = []
    for r, d, f in os.walk(path):
        for file in f:
            if '.csv' in file and 'future' not in r:
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
    def test_protocols_without_timeouts(self):
        files = get_files_list("tests/csv/")
        print("----------------------------------------------------------------------")
        print(".Testing on {} applications:".format(len(files)))
        for file in files:
            file_path = file.replace('.csv', '').replace('/csv/', '/pcap/')
            streamer_test = Streamer(source=file_path,
                                     capacity=64000,
                                     inactive_timeout=60000,
                                     active_timeout=60000)
            test_case_name = file_path.split('/')[-1].replace('.pcap', '')
            # print(test_case_name + ': ')
            exports = []
            for export in streamer_test:
                exports.append(export.debug())
            exports = sorted(exports)
            exports_ground_truth = flows_from_file(file)
            del streamer_test
            self.assertEqual(exports, exports_ground_truth)
        print(Fore.BLUE + 'OK' + Style.RESET_ALL)

    def test_unsupported_packet(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing on unsupported packet format:")
        streamer_test = Streamer(source='tests/pcap/future/quickplay.pcap',
                                 capacity=64000,
                                 inactive_timeout=60000,
                                 active_timeout=60000)
        exports = list(streamer_test)
        del streamer_test
        self.assertEqual(exports, [])
        print(Fore.BLUE + 'OK' + Style.RESET_ALL)

    def test_streamer_capacity(self):
        print("\n----------------------------------------------------------------------")
        print(".Testing warning Streamer capacity reached:")
        streamer_test = Streamer(source='tests/pcap/ajp.pcap',
                                 capacity=1,
                                 inactive_timeout=60000,
                                 active_timeout=60000)
        current_capacity = streamer_test.capacity
        streamer_test.capacity = current_capacity + 1
        current_capacity = streamer_test.capacity
        streamer_test.capacity = current_capacity - 1
        exports = list(streamer_test)
        del streamer_test
        self.assertEqual(exports[0].key,
                         FlowKey(ip_src=2887584147, ip_dst=2887584146, src_port=8010, dst_port=38856, ip_protocol=6))
        print(Fore.BLUE + 'OK' + Style.RESET_ALL)

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
        print('Inactive expiration: ' + Fore.BLUE + 'OK' + Style.RESET_ALL)

        streamer_test = Streamer(source='tests/pcap/expiration/small_instagram.pcap',
                                 capacity=100,
                                 inactive_timeout=60000,
                                 active_timeout=0)
        exports = list(streamer_test)
        del streamer_test
        self.assertEqual(len(exports), 39)
        print('Active expiration: ' + Fore.BLUE + 'OK' + Style.RESET_ALL)

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
        print('Flow to json: ' + Fore.BLUE + 'OK' + Style.RESET_ALL)


if __name__ == '__main__':
    unittest.main()