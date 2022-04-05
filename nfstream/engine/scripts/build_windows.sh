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

build_libgpgerror() {
  echo ""
  echo "---------------------------------------------------------------------------------------------------------------"
  echo "Compiling libgpg-error"
  echo "---------------------------------------------------------------------------------------------------------------"
  cd libgpg-error
  ./autogen.sh
  ./configure -enable-maintainer-mode --enable-static --enable-shared --with-pic --disable-doc --disable-nls
  make
  make DESTDIR=/tmp/nfstream_build install
  make clean
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

build_libgcrypt() {
  echo ""
  echo "---------------------------------------------------------------------------------------------------------------"
  echo "Compiling libgcrypt"
  echo "---------------------------------------------------------------------------------------------------------------"
  cd libgcrypt
  ./autogen.sh
  ./configure -enable-maintainer-mode --enable-static --enable-shared --with-pic --disable-doc CFLAGS="-I/tmp/nfstream_build/mingw64/include" LDFLAGS="-L/tmp/nfstream_build/mingw64/lib" --with-libgpg-error-prefix="/tmp/nfstream_build/mingw64"
  make
  make DESTDIR=/tmp/nfstream_build install
  make clean
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

build_libndpi() {
  echo ""
  echo "---------------------------------------------------------------------------------------------------------------"
  echo "Compiling libndpi"
  echo "---------------------------------------------------------------------------------------------------------------"
  cd nDPI
  env CFLAGS="-I/tmp/nfstream_build/mingw64/include" LDFLAGS="-L/tmp/nfstream_build/mingw64/lib" ./autogen.sh --with-local-libgcrypt
  make
  make DESTDIR=/tmp/nfstream_build install
  make clean
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

rm -rf /tmp/nfstream_build
cd nfstream/engine/dependencies
build_libgpgerror
build_libgcrypt
build_libndpi
echo ""
echo "---------------------------------------------------------------------------------------------------------------"
echo "Prepare engine_cc"
echo "---------------------------------------------------------------------------------------------------------------"
cd ..
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -DNDPI_CFFI_PREPROCESSING_EXCLUDE_PACKED -E -x c -P -C /tmp/nfstream_build/mingw64/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions.h
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -E -x c -P -C /tmp/nfstream_build/mingw64/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions_packed.h
gcc -E -x c -P -C lib_engine.c > /tmp/nfstream_build/lib_engine_cdefinitions.c
echo "---------------------------------------------------------------------------------------------------------------"
echo ""
cd ../..