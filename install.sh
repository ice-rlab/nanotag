#!/bin/bash
set -e

sudo apt update
sudo apt install -y build-essential cmake git python3 python3-pip clang

mkdir -p ~/mte-sanitizer-runtime

cd handler
clang -shared -fPIC -march=armv8.5-a+memtag -DINTERCEPT_SIGNAL_HANDLER -DFOPEN_INTERCEPT -DENABLE_DETAILED_REPORT -o ~/mte-sanitizer-runtime/handler.so handler.c
cd -

cd scudo
clang++ -fPIC -std=c++17 -march=armv8.5-a+memtag -msse4.2 -O2 -pthread -shared \
  -I standalone/include \
  standalone/*.cpp \
  -o ~/mte-sanitizer-runtime/libscudo.so
cd -

cd samples
clang test_oob_cross_granule.c -o test_oob_cross_granule
clang test_oob_short_granule.c -o test_oob_short_granule
cd -
