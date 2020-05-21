#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: __init__.py
This file is part of nfstream.

Copyright (C) 2019-20 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""


from .streamer import NFStreamer
from .plugin import NFPlugin
from .observer import NFObserver

"""
    streamer module is the core module of nfstream package.
"""

__author__ = """Zied Aouini"""
__email__ = 'aouinizied@gmail.com'
__version__ = '5.1.3'
