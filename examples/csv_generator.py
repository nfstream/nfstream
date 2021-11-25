"""
------------------------------------------------------------------------------------------------------------------------
csv_generator.py
Copyright (C) 2019-21 - NFStream Developers
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
import sys


if __name__ == '__main__':  # Mandatory if you are running on Windows Platform
    path = sys.argv[1]
    print("nfstream processing started. Use Ctrl+C to interrupt and save.")
    total_flows = NFStreamer(source=path,
                             statistical_analysis=True,
                             splt_analysis=10,
                             performance_report=1).to_csv()
