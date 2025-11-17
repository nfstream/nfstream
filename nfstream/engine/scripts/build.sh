#-----------------------------------------------------------------------------------------------------------------------
# build.sh
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
  ./configure --enable-ipv6 --disable-universal --enable-dbus=no --without-libnl --disable-rdma --without-dpdk
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
  ./autogen.sh
  CFLAGS="-I/tmp/nfstream_build/usr/local/include"
  LDFLAGS="-L/tmp/nfstream_build/usr/local/lib -L/tmp/nfstream_build/usr/local/lib64"
  CFLAGS=${CFLAGS} LDFLAGS=${LDFLAGS} ./configure && CFLAGS=${CFLAGS} LDFLAGS=${LDFLAGS} make
  make DESTDIR=/tmp/nfstream_build install
  make clean
  cd ..
  echo "---------------------------------------------------------------------------------------------------------------"
  echo ""
}

rm -rf /tmp/nfstream_build
cd nfstream/engine/dependencies
build_libpcap
build_libndpi

ARCH="$(uname -m)"
if [ "$ARCH" = "aarch64" ]; then
  echo "Applying aarch64 lib64→lib compatibility symlinks"
  # nDPI under /usr
  mkdir -p /tmp/nfstream_build/usr/lib
  for name in libndpi.a libndpi.so; do
    if [ -f "/tmp/nfstream_build/usr/lib64/$name" ] && [ ! -e "/tmp/nfstream_build/usr/lib/$name" ]; then
      ln -s "../lib64/$name" "/tmp/nfstream_build/usr/lib/$name"
    fi
  done
  # libpcap under /usr/local
  mkdir -p /tmp/nfstream_build/usr/local/lib
  for name in libpcap.a libpcap.so; do
    if [ -f "/tmp/nfstream_build/usr/local/lib64/$name" ] && [ ! -e "/tmp/nfstream_build/usr/local/lib/$name" ]; then
      ln -s "../lib64/$name" "/tmp/nfstream_build/usr/local/lib/$name"
    fi
  done
fi

echo ""
echo "---------------------------------------------------------------------------------------------------------------"
echo "Preprocessing engine_cc headers"
echo "---------------------------------------------------------------------------------------------------------------"
cd ..
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -DNDPI_CFFI_PREPROCESSING_EXCLUDE_PACKED -E -x c -P -C /tmp/nfstream_build/usr/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions.h
gcc -DNDPI_LIB_COMPILATION -DNDPI_CFFI_PREPROCESSING -E -x c -P -C /tmp/nfstream_build/usr/include/ndpi/ndpi_typedefs.h > /tmp/nfstream_build/ndpi_cdefinitions_packed.h
gcc -E -x c -P -C lib_engine.c > /tmp/nfstream_build/lib_engine_cdefinitions.c
echo "---------------------------------------------------------------------------------------------------------------"
echo ""
cd ../..
