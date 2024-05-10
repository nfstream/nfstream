"""
------------------------------------------------------------------------------------------------------------------------
utils.py
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

import json
import platform
import psutil
from threading import Timer
from collections import namedtuple
from enum import Enum, IntEnum


class NFEvent(Enum):
    FLOW = -1
    ERROR = -2
    SOCKET_CREATE = -3
    SOCKET_REMOVE = -4
    ALL_AFFINITY_SET = -5


class NFMode(IntEnum):
    SINGLE_FILE = 0
    INTERFACE = 1
    MULTIPLE_FILES = 2


InternalError = namedtuple('InternalError', ['id', 'message'])

InternalState = namedtuple('InternalState', ['id'])


def validate_flows_per_file(n):
    """ Simple parameter validator """
    if not isinstance(n, int) or isinstance(n, int) and n < 0:
        raise ValueError("Please specify a valid flows_per_file parameter (>= 0).")


def validate_rotate_files(n):
    """ Simple parameter validator """
    if not isinstance(n, int) or isinstance(n, int) and n < 0:
        raise ValueError("Please specify a valid rotate_files parameter (>= 0).")


def create_csv_file_path(path, source):
    """ File path creator """
    if path is None:
        if type(source) == list:
            return str(source[0]) + '.csv'
        return str(source) + '.csv'
    return path


def csv_converter(values):
    """ Convert non numeric values to string using their __str__ method and ensure proper quoting """
    for idx, value in enumerate(values):
        if not isinstance(value, float) and not isinstance(value, int):
            if value is None:
                values[idx] = ""
            else:
                values[idx] = str(values[idx])
                values[idx] = values[idx].replace('\"', '\\"')
                values[idx] = "\"" + values[idx] + "\""


def open_file(path, chunked, chunk_idx, rotate_files):
    """ File opener taking chunk mode into consideration """
    if not chunked:
        return open(path, 'wb')
    else:
        if rotate_files:
            return open(path.replace("csv", "{}.csv".format(chunk_idx % rotate_files)), 'wb')
        return open(path.replace("csv", "{}.csv".format(chunk_idx)), 'wb')


class PerformanceStats:
    """ Store all meter performance stats, `update_performances()` will be called if `NFStreamer`'s
    `performance_report` is set to non-zero value.
    
    Inherit this class and override `update_performances()` for custom log format. """

    def __init__(self, n_meters, context, is_linux, flows_count):
        self.is_linux = is_linux
        self.flows_count = flows_count
        self.performances = []
        for _ in range(n_meters):
            self.performances.append(
                {
                    "received": context.Value("I", 0),
                    "dropped": context.Value("I", 0),
                    "dropped_if": context.Value("I", 0),
                    "processed": context.Value("I", 0),
                    "ignored": context.Value("I", 0),
                }
            )

    def __getitem__(self, idx):
        return self.performances[idx]

    def update_performances(self):
        """ Update performance report """
        received = 0
        drops = 0
        drops_if = 0
        processed = 0
        ignored = 0
        load = []
        for meter in self.performances:
            if self.is_linux:
                received += meter["received"].value
                drops += meter["dropped"].value
                drops_if += meter["dropped_if"].value
                ignored += meter["ignored"].value
            else:
                received = max(meter["received"].value, received)
                drops = max(meter["dropped"].value, drops)
                drops_if = max(meter["dropped_if"].value, drops_if)
                ignored = max(meter["ignored"].value, ignored)
            processed += meter["processed"].value
            load.append(meter["processed"].value)
        print(json.dumps({"flows_expired": self.flows_count.value,
                          "packets_received": received,
                          "packets_processed": processed,
                          "packets_ignored": ignored,
                          "packets_dropped_filtered_by_kernel": drops,
                          "packets_dropped_filtered_by_interface": drops_if,
                          "meters_packets_processing_balance": load}))


class RepeatedTimer(object):
    """ Repeated timer thread """
    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False

            
def chunks_of_list(lst, n):
    """ create list of chunks of size n from a list"""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def set_affinity(idx):
    """ CPU affinity setter """
    if platform.system() == "Linux":
        c_cpus = psutil.Process().cpu_affinity()
        temp = list(chunks_of_list(c_cpus, 2))
        x = len(temp)
        try:
            psutil.Process().cpu_affinity(list(temp[idx % x]))
        except OSError as err:
            print("WARNING: failed to set CPU affinity ({err})".format(err))


def available_cpus_count():
    if platform.system() == "Linux":
        return len(psutil.Process().cpu_affinity())
    return psutil.cpu_count(logical=True)
