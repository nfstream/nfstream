"""
------------------------------------------------------------------------------------------------------------------------
prepare.py
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

import subprocess
import pathlib
import shutil
import sys
import os


BUILD_SCRIPT_PATH = str(pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")
                        .joinpath("scripts").joinpath("build")).replace("\\", "/").replace("//", "/")  # Patch for msys2


def build_engine_cc():
    if os.name != 'posix':  # Windows case, no libpcap
        build_script_command = r"""'{}'""".format(BUILD_SCRIPT_PATH + "_windows.sh")
        msys2 = shutil.which('msys2')
        subprocess.check_call([msys2, "-l", "-c", build_script_command], shell=True)
    else:
        if sys.platform == 'darwin':
            subprocess.check_call([BUILD_SCRIPT_PATH + "_macos.sh"], shell=True)
        else:
            subprocess.check_call([BUILD_SCRIPT_PATH + "_linux.sh"], shell=True)


if __name__ == "__main__":
    build_engine_cc()
