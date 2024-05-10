"""
------------------------------------------------------------------------------------------------------------------------
streamer.py
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

from multiprocessing import get_context
import threading
import pandas as pd
import time as tm
import os
import platform
import psutil
from collections.abc import Iterable
from os.path import isfile
from .meter import meter_workflow
from .anonymizer import NFAnonymizer
from .engine import is_interface
from .plugin import NFPlugin
from .utils import (
    csv_converter,
    open_file,
    RepeatedTimer,
    update_performances,
    set_affinity,
    available_cpus_count,
)
from .utils import (
    validate_flows_per_file,
    NFMode,
    create_csv_file_path,
    NFEvent,
    validate_rotate_files,
)
from .system import system_socket_worflow, match_flow_conn


class NFStreamer(object):
    streamer_id = 0  # class id generator
    glock = threading.Lock()
    is_windows = "windows" in platform.system().lower()

    """ Network Flow Streamer

    Examples:

        >>> from nfstream import NFStreamer
        >>> # Streamer object for reading traffic from a PCAP
        >>> streamer = NFStreamer(source='path/to/file.pcap')
        >>> # Converting data to pandas dataframe
        >>> df = streamer.to_pandas()

    """

    def __init__(
        self,
        source=None,
        decode_tunnels=True,
        bpf_filter=None,
        promiscuous_mode=True,
        snapshot_length=1536,
        socket_buffer_size=0,
        idle_timeout=120,  # https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt
        active_timeout=1800,
        accounting_mode=0,
        udps=None,
        n_dissections=20,
        statistical_analysis=False,
        splt_analysis=0,
        n_meters=0,
        max_nflows=0,
        performance_report=0,
        system_visibility_mode=0,
        system_visibility_poll_ms=100,
    ):
        with NFStreamer.glock:
            NFStreamer.streamer_id += 1
            self._idx = NFStreamer.streamer_id
        self._mode = NFMode.SINGLE_FILE
        self.source = source
        self.decode_tunnels = decode_tunnels
        self.bpf_filter = bpf_filter
        self.promiscuous_mode = promiscuous_mode
        self.snapshot_length = snapshot_length
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.accounting_mode = accounting_mode
        self.udps = udps
        self.n_dissections = n_dissections
        self.statistical_analysis = statistical_analysis
        self.splt_analysis = splt_analysis
        self.n_meters = n_meters
        self.max_nflows = max_nflows
        self.performance_report = performance_report
        self.system_visibility_mode = system_visibility_mode
        self.system_visibility_poll_ms = system_visibility_poll_ms

        # NIC socket buffer size. Default is 0, which means that the pcap default value is used.
        # The default values may vary depending on the OS and CPU architecture.
        # Range: 0 - 2^31-1
        self.socket_buffer_size = socket_buffer_size

        if NFStreamer.is_windows:
            self._mp_context = get_context("spawn")
        else:
            self._mp_context = get_context("fork")

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        if type(value) == list:  # List of pcap files to consider as a single one.
            if len(value) == 0:
                raise ValueError("Please provide a non-empty list of sources.")
            else:
                for i in range(len(value)):
                    try:
                        value[i] = str(os.fspath(value[i]))
                        if not isfile(value[i]):
                            raise TypeError
                    except TypeError:
                        raise ValueError(
                            "Invalid pcap file path at index: " + str(i) + "."
                        )
                self._mode = NFMode.MULTIPLE_FILES
        else:
            try:
                value = str(os.fspath(value))
            except TypeError:
                raise ValueError(
                    "Please specify a pcap file path or a valid network interface name as source."
                )
            if isfile(value):
                self._mode = NFMode.SINGLE_FILE
            else:
                interface = is_interface(value)
                if interface is not None:
                    self._mode = NFMode.INTERFACE
                    value = interface
                else:
                    raise ValueError(
                        "Please specify a pcap file path or a valid network interface name as source."
                    )
        self._source = value

    @property
    def decode_tunnels(self):
        return self._decode_tunnels

    @decode_tunnels.setter
    def decode_tunnels(self, value):
        if not isinstance(value, bool):
            raise ValueError(
                "Please specify a valid decode_tunnels parameter (possible values: True, False)."
            )
        self._decode_tunnels = value

    @property
    def bpf_filter(self):
        return self._bpf_filter

    @bpf_filter.setter
    def bpf_filter(self, value):
        if not isinstance(value, str) and value is not None:
            raise ValueError("Please specify a valid bpf_filter format.")
        self._bpf_filter = value

    @property
    def promiscuous_mode(self):
        return self._promiscuous_mode

    @promiscuous_mode.setter
    def promiscuous_mode(self, value):
        if not isinstance(value, bool):
            raise ValueError(
                "Please specify a valid promiscuous_mode parameter (possible values: True, False)."
            )
        self._promiscuous_mode = value

    @property
    def snapshot_length(self):
        return self._snapshot_length

    @snapshot_length.setter
    def snapshot_length(self, value):
        if not isinstance(value, int) or value <= 0:
            raise ValueError(
                "Please specify a valid snapshot_length parameter (positive integer)."
            )
        self._snapshot_length = value

    @property
    def socket_buffer_size(self):
        return self._socket_buffer_size

    @socket_buffer_size.setter
    def socket_buffer_size(self, value):
        if not isinstance(value, int) or (value < 0 or value > 2**31 - 1):
            raise ValueError(
                "Please specify a valid socket_buffer_size parameter (positive integer <= 2^31-1)."
            )
        self._socket_buffer_size = value

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, value):
        if not isinstance(value, int) or (
            (value < 0) or (value * 1000) > 18446744073709551615
        ):  # max uint64_t
            raise ValueError(
                "Please specify a valid idle_timeout parameter (positive integer in seconds)."
            )
        self._idle_timeout = value

    @property
    def active_timeout(self):
        return self._active_timeout

    @active_timeout.setter
    def active_timeout(self, value):
        if not isinstance(value, int) or (
            (value < 0) or (value * 1000) > 18446744073709551615
        ):  # max uint64_t
            raise ValueError(
                "Please specify a valid active_timeout parameter (positive integer in seconds)."
            )
        self._active_timeout = value

    @property
    def accounting_mode(self):
        return self._accounting_mode

    @accounting_mode.setter
    def accounting_mode(self, value):
        if not isinstance(value, int) or (value not in [0, 1, 2, 3]):
            raise ValueError(
                "Please specify a valid accounting_mode parameter (possible values: 0, 1, 2, 3)."
            )
        self._accounting_mode = value

    @property
    def udps(self):
        return self._udps

    @udps.setter
    def udps(self, value):
        multiple = isinstance(value, Iterable)
        if multiple:
            for plugin in value:
                if isinstance(plugin, NFPlugin):
                    pass
                else:
                    raise ValueError(
                        "User defined plugins must inherit from NFPlugin type."
                    )
            self._udps = value
        else:
            if isinstance(value, NFPlugin):
                self._udps = (value,)
            else:
                if value is None:
                    self._udps = ()
                else:
                    raise ValueError(
                        "User defined plugins must inherit from NFPlugin type."
                    )

    @property
    def n_dissections(self):
        return self._n_dissections

    @n_dissections.setter
    def n_dissections(self, value):
        if not isinstance(value, int) or (value < 0 or value > 255):
            raise ValueError(
                "Please specify a valid n_dissections parameter (possible values in : [0,...,255])."
            )
        self._n_dissections = value

    @property
    def statistical_analysis(self):
        return self._statistical_analysis

    @statistical_analysis.setter
    def statistical_analysis(self, value):
        if not isinstance(value, bool):
            raise ValueError(
                "Please specify a valid statistical_analysis parameter (possible values: True, False)."
            )
        self._statistical_analysis = value

    @property
    def splt_analysis(self):
        return self._splt_analysis

    @splt_analysis.setter
    def splt_analysis(self, value):
        if not isinstance(value, int) or (value < 0 or value > 65535):
            raise ValueError(
                "Please specify a valid splt_analysis parameter (possible values in : [0,...,65535])"
            )
        if value > 255:
            print(
                "[WARNING]: The specified splt_analysis parameter is higher than 255. High values can impact the performance of the tool."
            )
        self._splt_analysis = value

    @property
    def n_meters(self):
        return self._n_meters

    @n_meters.setter
    def n_meters(self, value):
        if isinstance(value, int) and value >= 0:
            pass
        else:
            raise ValueError(
                "Please specify a valid n_meters parameter (>=1 or 0 for auto scaling)."
            )
        c_cpus, c_cores = available_cpus_count(), psutil.cpu_count(logical=False)
        if (
            c_cores is None
        ):  # Patch for platforms returning None (https://github.com/giampaolo/psutil/issues/1078)
            c_cores = c_cpus
        if value == 0:
            if platform.system() == "Linux" and self._mode == NFMode.INTERFACE:
                self._n_meters = (
                    c_cpus - 1
                )  # We are in live capture mode and kernel fanout will be available
                #                              only on Linux, we set the n_meters to detected logical CPUs -1
            else:  # Windows, MacOS, offline capture
                if c_cpus >= c_cores:
                    if (
                        c_cpus == 2 * c_cores or c_cpus == c_cores
                    ):  # multi-thread or single threaded
                        self._n_meters = c_cores - 1
                    else:
                        self._n_meters = int(divmod(c_cpus / 2, 1)[0]) - 1
                else:  # weird case, fallback on cpu count.
                    self._n_meters = c_cpus - 1
        else:
            if (value + 1) <= c_cpus:
                self._n_meters = value
            else:  # avoid contention
                print(
                    "WARNING: n_meters set to :{} in order to avoid contention.".format(
                        c_cpus - 1
                    )
                )
                self._n_meters = c_cpus - 1
        if self._n_meters == 0:  # one CPU case
            self._n_meters = 1

    @property
    def max_nflows(self):
        return self._max_nflows

    @max_nflows.setter
    def max_nflows(self, value):
        if isinstance(value, int) and value >= 0:
            self._max_nflows = value - 1
        else:
            raise ValueError("Please specify a valid max_nflows parameter (>=0).")

    @property
    def performance_report(self):
        return self._performance_report

    @performance_report.setter
    def performance_report(self, value):
        if isinstance(value, int) and value >= 0:
            pass
        else:
            raise ValueError(
                "Please specify a valid performance_report parameter (>=1 for reporting interval (seconds)"
                " or 0 to disable). [Available only for Live capture]"
            )
        self._performance_report = value

    @property
    def system_visibility_mode(self):
        return self._system_visibility_mode

    @system_visibility_mode.setter
    def system_visibility_mode(self, value):
        if isinstance(value, int) and value in [0, 1]:
            if self._mode == NFMode.SINGLE_FILE and value > 0:
                print(
                    "WARNING: system_visibility_mode switched to 0 in offline capture "
                    "(available only for live capture)"
                )
                value = 0
            else:
                pass
        else:
            raise ValueError(
                "Please specify a valid system_visibility_mode parameter\n"
                "0: disable\n"
                "1: process information\n"
                "[Available only for live capture on the system generating the traffic]"
            )
        self._system_visibility_mode = value

    @property
    def system_visibility_poll_ms(self):
        return self._system_visibility_poll_ms

    @system_visibility_poll_ms.setter
    def system_visibility_poll_ms(self, value):
        if isinstance(value, int) and value >= 0:
            pass
        else:
            raise ValueError(
                "Please specify a valid system_visibility_poll_ms parameter "
                "(positive integer in milliseconds)"
            )
        self._system_visibility_poll_ms = value

    def __iter__(self):
        lock = self._mp_context.Lock()
        lock.acquire()
        meters = []
        performances = []
        n_terminated = 0
        child_error = None
        rt = None
        socket_listener = None
        browser_listener = None
        conn_cache = {}

        # To avoid issues on PyPy on Windows (See https://foss.heptapod.net/pypy/pypy/-/issues/3488), All
        # multiprocessing Value invocation must be performed before the call to Queue.
        n_meters = self.n_meters
        idx_generator = self._mp_context.Value("i", 0)
        for i in range(n_meters):
            performances.append(
                [
                    self._mp_context.Value("I", 0),
                    self._mp_context.Value("I", 0),
                    self._mp_context.Value("I", 0),
                ]
            )
        channel = self._mp_context.Queue(maxsize=32767)  # Backpressure strategy.
        #                                                  We set it to (2^15-1) to cope with OSX max semaphore value.
        group_id = os.getpid() + self._idx  # Used for fanout on Linux systems
        try:
            for i in range(n_meters):
                meters.append(
                    self._mp_context.Process(
                        target=meter_workflow,
                        args=(
                            self.source,
                            self.snapshot_length,
                            self.decode_tunnels,
                            self.bpf_filter,
                            self.promiscuous_mode,
                            n_meters,
                            i,
                            self._mode,
                            self.idle_timeout * 1000,
                            self.active_timeout * 1000,
                            self.accounting_mode,
                            self.udps,
                            self.n_dissections,
                            self.statistical_analysis,
                            self.splt_analysis,
                            channel,
                            performances[i],
                            lock,
                            group_id,
                            self.system_visibility_mode,
                            self.socket_buffer_size,
                        ),
                    )
                )
                meters[i].daemon = True  # demonize meter
                meters[i].start()
            if self._mode == NFMode.INTERFACE and self.performance_report > 0:
                if platform.system() == "Linux":
                    rt = RepeatedTimer(
                        self.performance_report,
                        update_performances,
                        performances,
                        True,
                        idx_generator,
                    )
                else:
                    rt = RepeatedTimer(
                        self.performance_report,
                        update_performances,
                        performances,
                        False,
                        idx_generator,
                    )
            if self._mode == NFMode.INTERFACE and self.system_visibility_mode:
                socket_listener = self._mp_context.Process(
                    target=system_socket_worflow,
                    args=(
                        channel,
                        self.idle_timeout * 1000,
                        self.system_visibility_poll_ms / 1000,
                    ),
                )
                socket_listener.daemon = True  # demonize socket_listener
                socket_listener.start()

            while True:
                try:
                    recv = channel.get()
                    if recv is None:  # termination and stats
                        n_terminated += 1
                        if n_terminated == n_meters:
                            break  # We finish up when all metering jobs are terminated
                    else:
                        if recv.id == NFEvent.ERROR:  # Error message
                            for i in range(n_meters):  # We break workflow loop
                                meters[i].terminate()
                            child_error = recv.message
                            break
                        elif recv.id == NFEvent.ALL_AFFINITY_SET:
                            set_affinity(
                                0
                            )  # we pin streamer to core 0 as it's the less intensive task and several services runs
                            #                  by default on this core.
                        elif recv.id == NFEvent.SOCKET_CREATE:
                            conn_cache[recv.key] = [recv.process_name, recv.process_pid]
                        elif recv.id == NFEvent.SOCKET_REMOVE:
                            del conn_cache[recv.key]
                        else:  # NFEvent.FLOW
                            recv.id = idx_generator.value  # Unify ID
                            idx_generator.value = idx_generator.value + 1
                            if (
                                self._mode == NFMode.INTERFACE
                                and self.system_visibility_mode
                            ):
                                recv = match_flow_conn(conn_cache, recv)
                            yield recv
                            if recv.id == self.max_nflows:
                                raise KeyboardInterrupt  # We reached the maximum flows count defined by the user.
                except KeyboardInterrupt:
                    for i in range(n_meters):  # We break workflow loop
                        meters[i].terminate()
                    break
            for i in range(n_meters):
                if meters[i].is_alive():
                    meters[i].join()  # Join metering jobs
            if self._mode == NFMode.INTERFACE and self.performance_report > 0:
                rt.stop()
            if self._mode == NFMode.INTERFACE and self.system_visibility_mode:
                socket_listener.terminate()
            channel.close()  # We close the queue
            channel.join_thread()  # and we join its thread
            if child_error is not None:
                raise ValueError(child_error)
        except (
            ValueError
        ) as observer_error:  # job initiation failed due to some bad observer parameters.
            raise ValueError(observer_error)

    def to_csv(
        self, path=None, columns_to_anonymize=(), flows_per_file=0, rotate_files=0
    ):
        validate_flows_per_file(flows_per_file)
        validate_rotate_files(rotate_files)
        chunked, chunk_idx = True, -1
        if flows_per_file == 0:
            chunked = False
        output_path = create_csv_file_path(path, self.source)
        total_flows, chunk_flows = 0, 0
        anon = NFAnonymizer(cols_names=columns_to_anonymize)
        f = None
        for flow in self:
            try:
                if total_flows == 0 or (
                    chunked and (chunk_flows > flows_per_file)
                ):  # header creation
                    if f is not None:
                        f.close()
                    chunk_flows = 1
                    chunk_idx += 1
                    f = open_file(output_path, chunked, chunk_idx, rotate_files)
                    header = ",".join([str(i) for i in flow.keys()]) + "\n"
                    f.write(header.encode("utf-8"))
                values = anon.process(flow)
                csv_converter(values)
                to_export = ",".join([str(i) for i in values]) + "\n"
                f.write(to_export.encode("utf-8"))
                total_flows = total_flows + 1
                chunk_flows += 1
            except KeyboardInterrupt:
                pass
        if f is not None:
            if not f.closed:
                f.close()
        return total_flows

    def to_pandas(self, columns_to_anonymize=()):
        """streamer to pandas function"""
        temp_file_path = "nfstream-{pid}-{iid}-{ts}.csv".format(
            pid=os.getpid(), iid=NFStreamer.streamer_id, ts=tm.time()
        )
        total_flows = self.to_csv(
            path=temp_file_path,
            columns_to_anonymize=columns_to_anonymize,
            flows_per_file=0,
        )
        if total_flows > 0:  # If there is flows, return Dataframe else return None.
            df = pd.read_csv(
                temp_file_path, engine="c"
            )  # Use C engine for superior performance (non-experimental)
            if total_flows != df.shape[0]:
                print(
                    "WARNING: {} flows ignored by pandas type conversion. Consider using to_csv() "
                    "method if drops are critical.".format(
                        abs(df.shape[0] - total_flows)
                    )
                )
        else:
            df = None
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return df
