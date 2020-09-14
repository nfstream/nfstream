#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
observer.py
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

def open_observer(src, snaplen, mode, promisc, ffi, lib):
    err_open = ffi.new("char []", 128)
    err_set = ffi.new("char []", 128)
    handler = lib.observer_open(bytes(src, 'utf-8'), snaplen, int(promisc), err_open, err_set, mode)
    if handler == ffi.NULL:
        ffi.dlclose(lib)
        raise ValueError("Failed to open and set defined source. Open error:{} , Set Error:{}".format(
            ffi.string(err_open).decode('ascii', 'ignore'),
            ffi.string(err_set).decode('ascii', 'ignore'))
        )
    return handler


def configure_observer(handler, bpf_filter, ffi, lib):
    if bpf_filter is not None:
        # On a valid handler, we set BPF filtering if defined.
        rs = lib.observer_configure(handler, bytes(bpf_filter, 'utf-8'))
        if rs > 0:
            lib.observer_close(handler)
            ffi.dlclose(lib)
            if rs == 1:
                raise ValueError("Failed to compile BPF filter:{}.".format(bpf_filter))
            else:
                raise ValueError("Failed to set BPF filter:{}.".format(bpf_filter))
    return handler


def update_stats(ffi, lib, handler, mode, tracker, processed, ignored):
    stat = ffi.new("struct nf_stat *")
    lib.observer_stats(handler, stat, mode)
    tracker[0].value = stat.dropped
    tracker[1].value = processed
    tracker[2].value = ignored


class NFObserver(object):
    """ NFObserver module main class """
    __slots__ = ("_cap", "lib", "ffi", "_mode", "_decode_tunnels", "_n_roots", "_root_idx", "_tracker")

    def __init__(self, cfg, ffi, lib):
        cap = open_observer(cfg.source, cfg.snaplen, cfg.mode, cfg.promisc, ffi, lib)
        cap = configure_observer(cap, cfg.bpf_filter, ffi, lib)
        self._cap = cap
        self.ffi = ffi
        self.lib = lib
        self._mode = cfg.mode
        self._decode_tunnels = cfg.decode_tunnels
        self._n_roots = cfg.n_roots
        self._root_idx = cfg.root_idx
        self._tracker = cfg.perf_track

    def __iter__(self):
        ffi = self.ffi
        lib = self.lib
        observer_cap = self._cap
        decode_tunnels = self._decode_tunnels
        n_roots = self._n_roots
        root_idx = self._root_idx
        observer_mode = self._mode
        observer_time = 0
        stat_time = 0
        go_stat = False
        processed = 0
        ignored = 0
        tracker = self._tracker
        try:
            while True:
                nf_packet = ffi.new("struct nf_packet *")
                ret = lib.observer_next(observer_cap, nf_packet, decode_tunnels, n_roots, root_idx, observer_mode)
                if ret > 0:  # Valid, must be processed by meter
                    time = nf_packet.time
                    if time > observer_time:
                        observer_time = time
                    else:
                        time = observer_time
                    if ret == 1:
                        processed += 1
                        yield 1, time, nf_packet
                    else:  # Time ticker (Valid but do not match our id)
                        yield 0, time, None
                    if observer_time - stat_time >= 1000: # refresh stats each second
                        stat_time = observer_time
                        go_stat = True
                    else:
                        go_stat = False
                elif ret == 0:  # Ignored
                    ignored += 1
                    pass
                elif ret == -1:  # Read error or empty buffer
                    pass
                else:  # End of file
                    raise KeyboardInterrupt
                if go_stat:
                    update_stats(ffi, lib, observer_cap, observer_mode, tracker, processed, ignored)

        except KeyboardInterrupt:
            return

    def close(self, channel):
        self.lib.observer_close(self._cap)
        channel.put(None)

