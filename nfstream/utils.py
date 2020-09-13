#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
streamer.py
Copyright (C) 2019-20 - NFStream Developers
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

def csv_converter(values):
    """ convert non numeric values to using their __str__ method and ensure quoting """
    for idx in range(len(values)):
        if not isinstance(values[idx], float) and not isinstance(values[idx], int):
            values[idx] = str(values[idx])
            values[idx] = values[idx].replace('\"', '\\"')
            values[idx] = "\"" + values[idx] + "\""


def open_file(path, chunked, chunk_idx):
    if not chunked:
        return open(path, 'wb')
    else:
        return open(path.replace("csv", "{}.csv".format(chunk_idx)), 'wb')