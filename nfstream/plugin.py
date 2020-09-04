#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
plugin.py
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


class NFPlugin(object):
    """ NFPlugin class """
    def __init__(self, **kwargs):
        """
        NFPlugin Parameters:
        kwargs : user defined named arguments that will be stored as Plugin attributes
        """
        for key, value in kwargs.items():
            setattr(self, key, value)

    def on_init(self, obs, entry):
        """
        on_init(self, obs, entry): Method called at entry creation.
        """
        pass

    def on_update(self, obs, entry):
        """
        on_update(self, obs, entry): Method called to update each entry with its belonging obs.
                                     When aggregating packets into flows, the entry is an NFEntry
                                     object and the obs is an NFPacket object.
        """
        pass

    def on_expire(self, entry):
        """
        on_expire(self, entry):      Method called at entry expiration. When aggregating packets
                                     into flows, the entry is an NFEntry
        """
        pass

    def cleanup(self):
        """
        cleanup(self):               Method called for plugin cleanup.
        """
        pass
