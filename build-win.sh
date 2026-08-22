#!/bin/sh
# Build Windows (mingw-w64) dentro de container arm64 debian:bookworm-slim.
set -e
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  g++-mingw-w64-x86-64-posix g++-mingw-w64-i686-posix make file > /dev/null

make clean > /dev/null || true

echo "== amd64 =="
make TARGET_OS=Windows_NT CXX=x86_64-w64-mingw32-g++-posix all
cp -v invpush.exe invpush-windows-amd64.exe

echo "== x86 =="
make clean > /dev/null
make TARGET_OS=Windows_NT CXX=i686-w64-mingw32-g++-posix all
cp -v invpush.exe invpush-windows-x86.exe

file invpush-windows-amd64.exe invpush-windows-x86.exe
ls -lh invpush-windows-*.exe
