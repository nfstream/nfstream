#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: flow.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""
from collections import namedtuple


class NFEntry(object):
    """ NFEntry base class """
    def __init__(self, obs, core, user, idx):
        self.id = idx
        for plugin in core:  # for each NFCache core plugin, we init and update
            setattr(self, plugin.name, plugin.on_init(obs))
        for plugin in user:  # for each NFCache core plugin, we init and update
            setattr(self, plugin.name, plugin.on_init(obs))

    def clean(self, core, user):
        """ Volatile attributes cleaner """
        for plugin in core:
            if plugin.volatile:
                plugin.on_expire(self)
                delattr(self, plugin.name)
        for plugin in user:
            if plugin.volatile:
                plugin.on_expire(self)
                delattr(self, plugin.name)
        return self

    def update(self, obs, core, user, to):
        """ Update a flow from a packet  """
        if obs.time - getattr(self, 'first_seen') >= to:
            setattr(self, 'expiration_id', 1)
            return self.clean(core, user)
        else:
            for plugin in core:  # for each NFCache core plugin, we update
                plugin.on_update(obs, self)
            for plugin in user:  # for each NFCache core plugin, we update
                plugin.on_update(obs, self)
            if getattr(self, 'expiration_id') < -1:  # custom export
                return self.clean(core, user)

    def idle(self, idle_timeout, time, core, user):
        """ Check if flow is idle """
        if time - getattr(self, 'last_seen') >= idle_timeout:
            return self.clean(core, user)
        else:
            return

    def __str__(self):
        """ String representation of flow """
        return str(namedtuple(type(self).__name__, self.__dict__.keys())(*self.__dict__.values()))
