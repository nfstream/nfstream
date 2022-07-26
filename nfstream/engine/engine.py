"""
------------------------------------------------------------------------------------------------------------------------
engine.py
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

from _lib_engine import ffi, lib


def setup_capture(ffi, lib, source, snaplen, promisc, mode, error_child, group_id):
    capture = lib.capture_open(bytes(source, 'utf-8'), int(mode), error_child)
    if capture == ffi.NULL:
        return
    fanout_set_failed = lib.capture_set_fanout(capture, int(mode), error_child, group_id)
    if fanout_set_failed:
        return
    timeout_set_failed = lib.capture_set_timeout(capture, int(mode), error_child)
    if timeout_set_failed:
        return
    promisc_set_failed = lib.capture_set_promisc(capture, int(mode), error_child, int(promisc))
    if promisc_set_failed:
        return
    snaplen_set_failed = lib.capture_set_snaplen(capture, int(mode), error_child, snaplen)
    if snaplen_set_failed:
        return
    return capture


def setup_filter(capture, lib, error_child, bpf_filter):
    """ Compile and setup BPF filter """
    if bpf_filter is not None:
        filter_set_failed = lib.capture_set_filter(capture, bytes(bpf_filter, 'utf-8'), error_child)
        if filter_set_failed:
            return False
    return True


def activate_capture(capture, lib, error_child, bpf_filter, mode):
    """ Capture activation function """
    activation_failed = lib.capture_activate(capture, int(mode), error_child)
    if activation_failed:
        return False
    return setup_filter(capture, lib, error_child, bpf_filter)


def setup_dissector(ffi, lib, n_dissections):
    """ Setup dissector according to n_dissections value """
    if n_dissections:  # Dissection activated
        # Check that headers and loaded library match and initiate dissector.
        checker = ffi.new("struct dissector_checker *")
        checker.flow_size = ffi.sizeof("struct ndpi_flow_struct")
        checker.flow_tcp_size = ffi.sizeof("struct ndpi_flow_tcp_struct")
        checker.flow_udp_size = ffi.sizeof("struct ndpi_flow_udp_struct")
        dissector = lib.dissector_init(checker)
        if dissector == ffi.NULL:
            return ffi.NULL
        # Configure it (activate bitmask to all protocols)
        lib.dissector_configure(dissector)
        return dissector
    return ffi.NULL


def is_interface(val):
    """ Check if val is a valid interface name and return it if true else None """
    intf = lib.capture_get_interface(val.encode('ascii'))
    if intf == ffi.NULL:
        return None
    return ffi.string(intf).decode('ascii', 'ignore')


def create_engine():
    """ engine creation function, return the loaded native nfstream engine and it's ffi interface"""
    return ffi, lib