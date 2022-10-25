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
    BROWSER_REQUEST = -5


class NFMode(IntEnum):
    SINGLE_FILE = 0
    INTERFACE = 1
    MULTIPLE_FILES = 2


InternalError = namedtuple('InternalError', ['id', 'message'])


def process_unify(proc_name):
    """ unify browser process names across platforms """
    proc_name = proc_name.lower()
    if proc_name == "chrome":
        proc_name = "chrome"
    else:
        if proc_name == "geckomain":
            proc_name = "firefox"
    return proc_name


def validate_flows_per_file(n):
    """ simple parameter validator """
    if not isinstance(n, int) or isinstance(n, int) and n < 0:
        raise ValueError("Please specify a valid flows_per_file parameter (>= 0).")


def validate_rotate_files(n):
    """ simple parameter validator """
    if not isinstance(n, int) or isinstance(n, int) and n < 0:
        raise ValueError("Please specify a valid rotate_files parameter (>= 0).")


def create_csv_file_path(path, source):
    """ file path creator """
    if path is None:
        if type(source) == list:
            return str(source[0]) + '.csv'
        return str(source) + '.csv'
    return path


def csv_converter(values):
    """ convert non numeric values to using their __str__ method and ensure quoting """
    for idx, value in enumerate(values):
        if not isinstance(value, float) and not isinstance(value, int):
            if value is None:
                values[idx] = ""
            else:
                values[idx] = str(values[idx])
                values[idx] = values[idx].replace('\"', '\\"')
                values[idx] = "\"" + values[idx] + "\""


def open_file(path, chunked, chunk_idx, rotate_files):
    """ File opener taking ckunk mode into consideration"""
    if not chunked:
        return open(path, 'wb')
    else:
        if rotate_files:
            return open(path.replace("csv", "{}.csv".format(chunk_idx % rotate_files)), 'wb')
        return open(path.replace("csv", "{}.csv".format(chunk_idx)), 'wb')


def update_performances(performances, is_linux, flows_count):
    """ Update performance report and check platform for consistency """
    drops = 0
    processed = 0
    ignored = 0
    load = []
    for meter in performances:
        if is_linux:
            drops += meter[0].value
            ignored += meter[2].value
        else:
            drops = max(meter[0].value, drops)
            ignored = max(meter[2].value, ignored)
        processed += meter[1].value
        load.append(meter[1].value)
    print(json.dumps({"flows_expired": flows_count.value,
                      "packets_processed": processed,
                      "packets_ignored": ignored,
                      "packets_dropped_filtered_by_kernel": drops,
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


def chunks(l, n):
    """ create list of chunks of size n from range l"""
    n = max(1, n)
    return (l[i:i+n] for i in range(0, len(l), n))


def set_affinity(idx):
    """ CPU affinity setter """
    if platform.system() == "Linux":
        c_cpus = psutil.cpu_count(logical=True)
        temp = list(chunks(range(c_cpus), 2))
        x = len(temp)
        psutil.Process().cpu_affinity(list(temp[idx % x]))
