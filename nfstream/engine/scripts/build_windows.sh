#-----------------------------------------------------------------------------------------------------------------------
# build_windows.sh
# Copyright (C) 2019-22 - NFStream Developers
# This file is part of NFStream, a Flexible Network Data Analysis Framework (https://www.nfstream.org/).
# NFStream is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
# version.
# NFStream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public License along with NFStream.
# If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------------------------------------------------------

setup_npcap() {
  echo ""
  echo "---------------------------------------------------------------------------------------------------------------"
  echo "Setup npcap SDK"
  echo "---------------------------------------------------------------------------------------------------------------"
  sdk=/tmp/nfstream_build/npcap-sdk-1.12.zip
  mkdir -p /tmp/nfstream_build

  # npcap.com is periodically unreachable or refuses the TLS handshake. Retry, write to a
  # fixed path so a partial download cannot be left behind under a .1 suffix, and fail
  # loudly here rather than hundreds of lines later in the compiler.
  downloaded=false
  for attempt in 1 2 3 4 5; do
    rm -f "$sdk"

    if wget --tries=3 --timeout=30 -O "$sdk" https://npcap.com/dist/npcap-sdk-1.12.zip; then
      downloaded=true
      break
    fi

    if [ "$attempt" -lt 5 ]; then
      echo "Npcap SDK download attempt $attempt failed; retrying in 15 seconds"
      sleep 15
    fi
  done

  [ "$downloaded" = true ] || {
    echo "ERROR: unable to download the Npcap SDK" >&2
    return 1
  }

  unzip -o "$sdk" -d /tmp/nfstream_build/npcap/ || {
    echo "ERROR: unable to extract the Npcap SDK" >&2
    return 1
  }

  [ -f /tmp/nfstream_build/npcap/Include/pcap.h ] || {
    echo "ERROR: Npcap SDK is missing Include/pcap.h" >&2
    return 1
  }

  [ -f /tmp/nfstream_build/npcap/Lib/x64/wpcap.lib ] || {
    echo "ERROR: Npcap SDK is missing Lib/x64/wpcap.lib" >&2
    return 1
  }
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

build_libndpi() {
  echo ""
  echo "---------------------------------------------------------------------------------------------------------------"
  echo "Compiling libndpi"
  echo "---------------------------------------------------------------------------------------------------------------"
  # nDPI 5.0 configure requires libpcap-dev when using --with-only-libndpi on MinGW
  pacman -S --noconfirm mingw-w64-x86_64-libpcap
  cd nDPI
  ./autogen.sh
  # nDPI 5.0: Build only the library, not example applications (--with-only-libndpi)
  # Disable global context to avoid pthread dependency (MinGW pthread not linkable by MSVC)
  ./configure --with-only-libndpi --disable-global-context-support && make
  make DESTDIR=/tmp/nfstream_build install
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

rm -rf /tmp/nfstream_build
cd $1/dependencies
setup_npcap || exit 1
build_libndpi
echo ""
echo "---------------------------------------------------------------------------------------------------------------"
echo "Preprocessing engine_cc headers"
echo "---------------------------------------------------------------------------------------------------------------"
cd ..
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -DNDPI_CFFI_PREPROCESSING_EXCLUDE_PACKED -E -x c -P -C /tmp/nfstream_build/mingw64/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions.h
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -E -x c -P -C /tmp/nfstream_build/mingw64/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions_packed.h
gcc -E -x c -P -C lib_engine.c > /tmp/nfstream_build/lib_engine_cdefinitions.c
sed -i 's/#include <getopt.h>//g' /tmp/nfstream_build/mingw64/include/ndpi/ndpi_win32.h
gcc --version > /tmp/nfstream_build/gcc_version.in
echo "---------------------------------------------------------------------------------------------------------------"
echo ""
cd ../..