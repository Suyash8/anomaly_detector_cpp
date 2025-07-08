#! /bin/bash

rm -rf build
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=$(pwd)/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release