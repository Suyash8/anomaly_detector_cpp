# --- Project Definition ---
# Defines the minimum version of CMake required and sets the project name,
# version, and language. This is the standard header for any CMake project.
cmake_minimum_required(VERSION 3.16)
project(AnomalyDetector VERSION 1.0.0 LANGUAGES CXX)

# --- Set C++ Standard ---
# Enforce C++17, which is required by the project's source code.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Placeholder for future steps
message(STATUS "Initial CMake configuration complete.")