#!/bin/bash

# Clean previous build artifacts
rm -rf build

# Default mode
MODE="release"
BUILD_TESTS=OFF
RUN_APP=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        release)
            MODE="release"
            ;;
        test)
            MODE="test"
            BUILD_TESTS=ON
            ;;
        run)
            RUN_APP=true
            ;;
        *)
            # Handle unknown arguments as they indicate a custom build mode
            ;;
    esac
done

# Configure CMake options
CMAKE_OPTIONS="-DCMAKE_TOOLCHAIN_FILE=$(pwd)/vcpkg/scripts/buildsystems/vcpkg.cmake -DBUILD_TESTING=$BUILD_TESTS"

# Run CMake configure
cmake -B build -S . ${CMAKE_OPTIONS}

# Build the project
cmake --build build --config Release

# Run tests if in 'test' mode and 'run' was NOT requested
if [[ "$BUILD_TESTS" == "ON" && "$RUN_APP" == false ]]; then
    echo -e "\nBuilding with tests enabled, but not running the app."
fi

if [[ "$BUILD_TESTS" == "ON" && "$RUN_APP" == true ]]; then
    echo -e "\nRunning tests..."
    (cd build && ctest --output-on-failure)
fi

# If 'run' was requested, run the application (but not if in test mode)
if [[ "$RUN_APP" == true && "$MODE" != "test" ]]; then
    echo -e "\nRunning application..."
    ./build/anomaly_detector config.ini
fi
