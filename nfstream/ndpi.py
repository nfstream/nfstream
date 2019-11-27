"""
file: ndpi.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from .libndpi_cc import cc, cc_ndpi_network_headers, cc_ndpi_id_struct, cc_ndpi_flow_tcp_struct
from .libndpi_cc import cc_ndpi_flow_udp_struct, cc_ndpi_int_one_line_struct, cc_ndpi_packet_struct
from .libndpi_cc import cc_ndpi_packet_struct_stack, cc_ndpi_apis
from os.path import abspath, dirname
import cffi


class NDPI():
    def __init__(self):
        self._ffi = cffi.FFI()
        self._ndpi = self._ffi.dlopen(dirname(abspath(__file__)) + '/libs/libndpi.so')
        self._ffi.cdef(cc)
        self._ffi.cdef(cc_ndpi_network_headers, packed=True)
        self._ffi.cdef(cc_ndpi_id_struct)
        self._ffi.cdef(cc_ndpi_flow_tcp_struct, packed=True)
        self._ffi.cdef(cc_ndpi_flow_udp_struct, packed=True)
        self._ffi.cdef(cc_ndpi_int_one_line_struct)
        self._ffi.cdef(cc_ndpi_packet_struct_stack, packed=True)
        self._ffi.cdef(cc_ndpi_packet_struct)
        self._ffi.cdef(cc_ndpi_apis)
        self._mod = self._ndpi.ndpi_init_detection_module()
        all = self._ffi.new('NDPI_PROTOCOL_BITMASK*')
        self._ndpi.memset(self._ffi.cast("char *", all), 0xFF, self._ffi.sizeof("NDPI_PROTOCOL_BITMASK"))
        self._ndpi.ndpi_set_protocol_detection_bitmask2(self._mod, all)
        self.SIZEOF_FLOW_STRUCT = self._ffi.sizeof("struct ndpi_flow_struct")
        self.SIZEOF_ID_STRUCT = self._ffi.sizeof("struct ndpi_id_struct")
        self.NULL = self._ffi.NULL

    def new_ndpi_flow(self):
        f = self._ffi.cast('struct ndpi_flow_struct*', self._ndpi.ndpi_flow_malloc(self.SIZEOF_FLOW_STRUCT))
        self._ndpi.memset(f, 0, self.SIZEOF_FLOW_STRUCT)
        return f

    def new_ndpi_id(self):
        i = self._ffi.cast('struct ndpi_id_struct*', self._ndpi.ndpi_malloc(self.SIZEOF_ID_STRUCT))
        self._ndpi.memset(i, 0, self.SIZEOF_ID_STRUCT)
        return i

    def ndpi_detection_process_packet(self, flow, packet, packetlen, current_tick, src, dst):
        return self._ndpi.ndpi_detection_process_packet(self._mod, flow, packet, packetlen, current_tick, src, dst)

    def ndpi_detection_giveup(self, flow):
        return self._ndpi.ndpi_detection_giveup(self._mod, flow, 1, self._ffi.new("uint8_t*", 0))

    def ndpi_flow_free(self, flow):
        return self._ndpi.ndpi_flow_free(flow)

    def ndpi_free(self, ptr):
        return self._ndpi.ndpi_free(ptr)

    def get_str_field(self, ptr):
        return self._ffi.string(ptr).decode('utf-8', errors='ignore')

    def ndpi_protocol2name(self, proto):
        buf = self._ffi.new("char[32]")
        self._ndpi.ndpi_protocol2name(self._mod, proto, buf, self._ffi.sizeof(buf))
        return self._ffi.string(buf).decode('utf-8', errors='ignore')

    def ndpi_category_get_name(self, category):
        return self._ffi.string(self._ndpi.ndpi_category_get_name(self._mod, category)).decode('utf-8', errors='ignore')

    def ndpi_exit_detection_module(self):
        self._ndpi.ndpi_exit_detection_module(self._mod)
