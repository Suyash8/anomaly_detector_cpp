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
find_package(nlohmann_json REQUIRED)
find_package(httplib REQUIRED)
find_package(mongocxx REQUIRED)
find_package(Threads REQUIRED) # For pthread, which was a linker flag in the makefile

# --- Source File Discovery ---
# Automatically find all .cpp files in the 'src' directory and its subdirectories.
file(GLOB_RECURSE CORE_SOURCES 
    "src/analysis/*.cpp"
    "src/core/*.cpp"
    "src/detection/*.cpp"
    "src/io/*.cpp"
    "src/io/alert_dispatch/*.cpp"
    "src/io/db/*.cpp"
    "src/io/log_readers/*.cpp"
    "src/io/threat_intel/*.cpp"
    "src/models/*.cpp"
    "src/utils/*.cpp"
)

# --- Define the Core Logic Library ---
# This creates a static library named 'ad_core' containing all our application logic.
add_library(ad_core STATIC ${CORE_SOURCES})

# # --- Define the Executable Target ---
# # This command creates the `anomaly_detector` executable from the discovered source files.
# add_executable(anomaly_detector ${SOURCES})

# --- Set Include Directories ---
set(ONNX_RUNTIME_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/onnxruntime)

# Tell the compiler to look for headers in the 'src' directory.
target_include_directories(ad_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${ONNX_RUNTIME_ROOT}/include"
)

# --- Set Link Directories ---
target_link_directories(ad_core PUBLIC
    "${ONNX_RUNTIME_ROOT}/lib"
)

# --- Link Libraries to the Target ---
# This is the modern way to link dependencies. It automatically handles include paths,
# library paths, and any necessary linker flags for each dependency.
target_link_libraries(ad_core PUBLIC
    nlohmann_json::nlohmann_json
    onnxruntime
    httplib::httplib
    mongo::mongocxx_static
    mongo::bsoncxx_static
    Threads::Threads
)

# --- Set Compile Definitions ---
# This is the portable equivalent of the -D flag in the Makefile.
target_compile_definitions(ad_core PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
)

# --- Set Compiler-Specific Flags for Warnings ---
# This is a portable way to add warning flags for specific compilers.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(ad_core PRIVATE -Wall -Wextra -pedantic)
endif()

# --- Define the Main Executable Target ---
# The main executable is now very simple: just main.cpp.
add_executable(anomaly_detector src/main.cpp)

# Link the main executable against our core logic library.
# This gives main.cpp access to all the classes like AnalysisEngine, etc.
target_link_libraries(anomaly_detector PRIVATE ad_core)

# --- Utility Target for Log Generator ---
# This creates a separate, simple build target for the log generator utility,
# which is not part of the main application logic. It can be built with
# `cmake --build build --target log_generator`.
add_executable(log_generator log_generator.cpp)

# --- Installation Rules ---
# This section defines what happens when `cmake --install` is run. It creates
# a clean, distributable layout for the application and its required data files.

# Install the main executable to a 'bin' directory.
install(TARGETS anomaly_detector
    RUNTIME DESTINATION bin
)

# Install the default configuration file to an 'etc' directory.
install(FILES config.ini
    DESTINATION etc
)

# Install the ML models and data files to a shared data directory.
install(DIRECTORY src/models/ DESTINATION share/anomaly_detector/models
    FILES_MATCHING PATTERN "*.onnx" PATTERN "*.json"
)

install(FILES data/allowlist.txt DESTINATION share/anomaly_detector/data)

# --- Testing Setup ---
# This block is only enabled when -DBUILD_TESTING=ON is passed to CMake.
option(BUILD_TESTING "Build the unit and integration tests" ON)
if(BUILD_TESTING)
    message(STATUS "Building with tests enabled.")

    find_package(GTest CONFIG REQUIRED)
    include(GoogleTest)

    # Create a directory for test source files
    file(GLOB_RECURSE TEST_SOURCES "tests/*.cpp")

    # Define the test executable
    add_executable(run_tests ${TEST_SOURCES} ${SOURCES})
    set_property(TARGET run_tests PROPERTY WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

    # Link the test executable to GTest and all the project's dependencies
    # so that our tests can use them.
    target_link_libraries(run_tests PRIVATE
        ad_core
        GTest::gtest_main
    )

    include(CTest)

    gtest_discover_tests(run_tests)
endif()