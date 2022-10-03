"""
------------------------------------------------------------------------------------------------------------------------
wfeatures_pandas.py
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
import sys

try:
    from nfstream.plugins.wfeatures import WFPlugin
except ImportError:
    print("Please install pywt: pip install pywt")
    sys.exit(1)



if __name__ == '__main__':  # Mandatory if you are running on Windows Platform
    path = sys.argv[1]
    print("nfstream processing started. Use Ctrl+C to interrupt and save.")
    streamer = NFStreamer(source=path, active_timeout=41, udps=WFPlugin(active_timeout=41, levels=12))
    print("Converting to pandas...")
    df = streamer.to_pandas()
    print("Dataframe: ")
    print(df.head())
    print("With columns: ")
    print(df.columns.tolist())
