#-----------------------------------------------------------------------------------------------------------------------
# build_linux.sh
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

build_libpcap() {
  echo ""
  echo "---------------------------------------------------------------------------------------------------------------"
  echo "Compiling libpcap (fanout)"
  echo "---------------------------------------------------------------------------------------------------------------"
  cd libpcap
  ./configure --enable-ipv6 --disable-universal --enable-dbus=no --without-libnl
  make
  make DESTDIR=/tmp/nfstream_build install
  make clean
  cd ..
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
  ./configure -enable-maintainer-mode --enable-static --enable-shared --with-pic --disable-doc CFLAGS="-I/tmp/nfstream_build/usr/local/include" LDFLAGS="-L/tmp/nfstream_build/usr/local/lib" --with-libgpg-error-prefix="/tmp/nfstream_build/usr/local"
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
  gcc --version
  sed -i 's/PKG_CHECK_MODULES/dnl> /g' configure.ac
  env CFLAGS="-I/tmp/nfstream_build/usr/local/include" LDFLAGS="-L/tmp/nfstream_build/usr/local/lib" ./autogen.sh --with-local-libgcrypt
  make
  make DESTDIR=/tmp/nfstream_build install
  make clean
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

rm -rf /tmp/nfstream_build
cd nfstream/engine/dependencies
build_libpcap
build_libgpgerror
build_libgcrypt
build_libndpi
echo ""
echo "---------------------------------------------------------------------------------------------------------------"
echo "Prepare engine_cc"
echo "---------------------------------------------------------------------------------------------------------------"
cd ..
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -DNDPI_CFFI_PREPROCESSING_EXCLUDE_PACKED -E -x c -P -C /tmp/nfstream_build/usr/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions.h
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -E -x c -P -C /tmp/nfstream_build/usr/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions_packed.h
gcc -E -x c -P -C lib_engine.c > /tmp/nfstream_build/lib_engine_cdefinitions.c
echo "---------------------------------------------------------------------------------------------------------------"
echo ""
cd ../..