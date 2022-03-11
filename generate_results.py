"""
------------------------------------------------------------------------------------------------------------------------
generate_results.py
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

from nfstream import NFStreamer
from tqdm import tqdm
import os


def get_files_list(path):
    files = []
    for r, d, f in os.walk(path):
        for file in f:
            if '.pcap' == file[-5:] or ".pcapng" == file[-7:]:  # Pick out only pcaps files
                files.append(os.path.join(r, file))
    files.sort()
    return files


pcap_files = get_files_list(os.path.join("tests", "pcaps"))
for pcap_file in tqdm(pcap_files):
    df = NFStreamer(source=pcap_file, n_dissections=20, n_meters=1).to_pandas()[["id",
                                                                                 "bidirectional_packets",
                                                                                 "bidirectional_bytes",
                                                                                 "application_name",
                                                                                 "application_category_name",
                                                                                 "application_is_guessed",
                                                                                 "application_confidence"]]
    df.to_csv(pcap_file.replace("pcaps",
                                "results"),
              index=False)