"""
------------------------------------------------------------------------------------------------------------------------
plugin.py
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


class NFPlugin(object):
    """ NFPlugin class: Main entry point to extend NFStream """
    def __init__(self, **kwargs):
        """
        NFPlugin Parameters:
        kwargs : user defined named arguments that will be stored as Plugin attributes
        """
        for key, value in kwargs.items():
            setattr(self, key, value)

    def on_init(self, packet, flow):
        """
        on_init(self, obs, flow): Method called at flow creation.
        You must initiate your udps values if you plan to compute ones.
        Example: -------------------------------------------------------
                 flow.udps.magic_message = "NO"
                 if packet.raw_size == 40:
                    flow.udps.packet_40_count = 1
                 else:
                    flow.udps.packet_40_count = 0
        ----------------------------------------------------------------
        """

    def on_update(self, packet, flow):
        """
        on_update(self, obs, flow): Method called to update each flow with its belonging packet.
        Example: -------------------------------------------------------
                 if packet.raw_size == 40:
                    flow.udps.packet_40_count += 1
        ----------------------------------------------------------------
        """

    def on_expire(self, flow):
        """
        on_expire(self, flow):      Method called at flow expiration.
        Example: -------------------------------------------------------
                 if flow.udps.packet_40_count >= 10:
                    flow.udps.magic_message = "YES"
        ----------------------------------------------------------------
        """

    def cleanup(self):
        """
        cleanup(self):               Method called for plugin cleanup.
        Example: -------------------------------------------------------
                 del self.large_dict_passed_as_plugin_attribute
        ----------------------------------------------------------------
        """
