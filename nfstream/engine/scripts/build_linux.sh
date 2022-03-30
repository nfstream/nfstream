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
  # patch for aarch64 (see https://dev.gnupg.org/T4317)
  sed -i 's/.globl _gcry_camellia_arm_tables//g' cipher/camellia-aarch64.S
  ./autogen.sh
  ./configure -enable-maintainer-mode --enable-static --enable-shared --with-pic --disable-doc CFLAGS="-I/tmp/nfstream_build/usr/local/include" LDFLAGS="-L/tmp/nfstream_build/usr/local/lib" --with-libgpg-error-prefix="/tmp/nfstream_build/usr/local"
  make
  make DESTDIR=/tmp/nfstream_build install
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
  env CFLAGS="-I/tmp/nfstream_build/usr/local/include" LDFLAGS="-L/tmp/nfstream_build/usr/local/lib" ./autogen.sh --with-local-libgcrypt
  make
  make DESTDIR=/tmp/nfstream_build install
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
  }

cd nfstream/engine/dependencies
build_libpcap
build_libgpgerror
build_libgcrypt
build_libndpi
cd ..
echo ""
echo "---------------------------------------------------------------------------------------------------------------"
echo "Compiling engine_cc"
echo "---------------------------------------------------------------------------------------------------------------"
gcc -I/tmp/nfstream_build/usr/local/include -I/tmp/nfstream_build/usr/include/ndpi/ -shared -o engine_cc.so -g -fPIC -DPIC -O2 -Wall engine_cc.c /tmp/nfstream_build/usr/local/lib/libpcap.a /tmp/nfstream_build/usr/lib/libndpi.a /tmp/nfstream_build/usr/local/lib/libgcrypt.a /tmp/nfstream_build/usr/local/lib/libgpg-error.a
echo "---------------------------------------------------------------------------------------------------------------"
echo ""
rm -rf /tmp/nfstream_build
