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

import platform
import subprocess
import pathlib
import sys
import os

BUILD_SCRIPT_PATH = str(pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")
                        .joinpath("scripts").joinpath("build"))

# Patched path as it is passed to msys2 bash
ENGINE_PATH = str(pathlib.Path(__file__).parent.resolve().joinpath("nfstream").joinpath("engine")).replace("\\", "/")


def prepare_lib_engine_requirements():
    if os.name != 'posix':  # Windows case
        os.environ["MSYSTEM"] = "MINGW64"
        msys = os.getenv("MSYS2_PATH")
        if msys is None:
            os.environ["MSYS2_PATH"] = "C:/msys64"
        msys = os.getenv("MSYS2_PATH")
        build_script_command = r"""'{}'""".format(str(BUILD_SCRIPT_PATH) + "_windows.sh")
        subprocess.check_call(["{msys}/usr/bin/bash".format(msys=msys).replace("/", "\\"),
                               "-l",
                               build_script_command, ENGINE_PATH],
                              shell=True)
    else:
        if sys.platform == 'darwin':
            subprocess.check_call([str(BUILD_SCRIPT_PATH) + "_macos.sh"], shell=True)
        elif "aarch" in platform.machine():
            subprocess.check_call([str(BUILD_SCRIPT_PATH) + "_aarch64.sh"], shell=True)
        else:
            subprocess.check_call([str(BUILD_SCRIPT_PATH) + "_linux.sh"], shell=True)


if __name__ == "__main__":
    prepare_lib_engine_requirements()