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
  wget https://npcap.com/dist/npcap-sdk-1.12.zip -P /tmp/nfstream_build/
  unzip /tmp/nfstream_build/npcap-sdk-1.12.zip -d /tmp/nfstream_build/npcap/
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

build_libndpi() {
  echo ""
  echo "---------------------------------------------------------------------------------------------------------------"
  echo "Compiling libndpi"
  echo "---------------------------------------------------------------------------------------------------------------"
  cd nDPI
  ./autogen.sh
  make
  make DESTDIR=/tmp/nfstream_build install
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

rm -rf /tmp/nfstream_build
cd $1/dependencies
setup_npcap
build_libndpi
echo ""
echo "---------------------------------------------------------------------------------------------------------------"
echo "Prepare engine_cc"
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