#!/bin/bash

set -ex

OPENSSL_VERS=1.0.2l
OPENSSL_SHA256=ce07195b659e75f4e1db43552860070061f156a98bb37b672b101ba6e3ddf30c

OPENSSL_OS=linux-x86_64
OPENSSL_CC=gcc
OPENSSL_AR=ar

TARGET=$OPENSSL_OS

mkdir -p target/$TARGET/openssl
install=`pwd`/target/$TARGET/openssl/openssl-install
out=`pwd`/target/$TARGET/openssl/openssl-$OPENSSL_VERS.tar.gz
curl -o $out https://www.openssl.org/source/openssl-$OPENSSL_VERS.tar.gz
sha256sum $out > $out.sha256
test $OPENSSL_SHA256 = `cut -d ' ' -f 1 $out.sha256`

tar xf $out -C target/$TARGET/openssl
(cd target/$TARGET/openssl/openssl-$OPENSSL_VERS && \
     CC=$OPENSSL_CC \
       AR=$OPENSSL_AR \
       $SETARCH ./Configure --prefix=$install no-dso $OPENSSL_OS $OPENSSL_CFLAGS -fPIC && \
     make -j4 && \
     make install)

export OPENSSL_STATIC=1
export OPENSSL_DIR=$install
export OPENSSL_ROOT_DIR=$install
export OPENSSL_LIB_DIR=$install/lib
export OPENSSL_INCLUDE_DIR=$install/include

cargo build --release
