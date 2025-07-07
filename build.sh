#! /bin/bash

rm -rf build
cmake -B -S . -DCMAKE_TOOLCHAIN_FILE=$(pwd)/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release