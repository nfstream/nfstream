#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: csv_generator.py
This file is part of nfstream.

Copyright (C) 2019-20 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from nfstream import NFStreamer
import sys
import datetime


path = sys.argv[1]
output_file_name = path + ".csv"
print("nfstream processing started. Use Ctrl+C to interrupt and save.")
start = datetime.datetime.now()
total_flows = NFStreamer(source=path, statistics=True).to_csv(path=output_file_name, sep=";")
end = datetime.datetime.now()
print("\nnfstream processed {} flows and saved them in file: {}".format(total_flows, output_file_name))
print("Processing time: {}".format(end - start))
