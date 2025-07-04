# --- Project Definition ---
# Defines the minimum version of CMake required and sets the project name,
# version, and language. This is the standard header for any CMake project.
cmake_minimum_required(VERSION 3.16)
project(AnomalyDetector VERSION 1.0.0 LANGUAGES CXX)

# --- Set C++ Standard ---
# Enforce C++17, which is required by the project's source code.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Find Dependencies (handled by vcpkg) ---
# These commands instruct CMake to find the libraries that vcpkg has installed.
# The `REQUIRED` keyword will cause CMake to fail if a library is not found.
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(onnxruntime 1.10.0 REQUIRED)
find_package(httplib 0.11.3 REQUIRED)
find_package(Threads REQUIRED) # For pthread, which was a linker flag in the makefile

# --- Source File Discovery ---
# Automatically find all .cpp files in the 'src' directory and its subdirectories.
# This is more maintainable than listing each file manually.
file(GLOB_RECURSE SOURCES "src/*.cpp")

# --- Define the Executable Target ---
# This command creates the `anomaly_detector` executable from the discovered source files.
add_executable(anomaly_detector ${SOURCES})

# --- Set Include Directories ---
# Tell the compiler to look for headers in the 'src' directory.
target_include_directories(anomaly_detector PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# --- Link Libraries to the Target ---
# This is the modern way to link dependencies. It automatically handles include paths,
# library paths, and any necessary linker flags for each dependency.
target_link_libraries(anomaly_detector PUBLIC
    nlohmann_json::nlohmann_json
    onnxruntime::onnxruntime
    httplib::httplib
    Threads::Threads
)

# --- Set Compile Definitions ---
# This is the portable equivalent of the -D flag in the Makefile.
target_compile_definitions(anomaly_detector PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
)

# --- Set Compiler-Specific Flags for Warnings ---
# This is a portable way to add warning flags for specific compilers.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(anomaly_detector PRIVATE -Wall -Wextra -pedantic)
endif()

# --- Utility Target for Log Generator ---
# This creates a separate, simple build target for the log generator utility,
# which is not part of the main application logic. It can be built with
# `cmake --build build --target log_generator`.
add_executable(log_generator log_generator.cpp)