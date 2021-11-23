"""
------------------------------------------------------------------------------------------------------------------------
test_dll.py
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

from os.path import abspath, dirname
import cffi

# gcc -Indpi_includes -shared -o test_dll.dll -g -O2 -Wall test_dll.c libndpi.a libws2_32.a

cc_dll_apis = """
uint16_t get_ndpi_api_version(void);
const char *pcap_lib_version(void);
"""

ffi = cffi.FFI()
engine_lib = ffi.dlopen(dirname(abspath(__file__)) + '/test_dll.dll')
ffi.cdef(cc_dll_apis)
print("TEST ENGINE DLL LOAD:get_ndpi_api_version")
print(engine_lib.get_ndpi_api_version())
print("TEST NPCAP DLL LOAD:pcap_lib_version")
pcap_lib = ffi.dlopen("C:\\Windows\\System32\\Npcap\\wpcap.dll")
print(ffi.string(pcap_lib.pcap_lib_version()).decode('utf-8', errors='ignore'))
