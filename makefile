# Compiler and flags
CXX = g++

# --- Common Flags ---
# Flags used for both debug and release compilation
COMMON_CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -Isrc -Ithird_party/cpp-httplib -Ithird_party/nlohmann -Ithird_party/onnxruntime/include

# --- Release Specific Flags ---
RELEASE_CXXFLAGS = $(COMMON_CXXFLAGS) -O3 -DCPPHTTPLIB_OPENSSL_SUPPORT

# --- Debug Specific Flags ---
DEBUG_CXXFLAGS = $(COMMON_CXXFLAGS) -g -O0 -DCPPHTTPLIB_OPENSSL_SUPPORT

# --- Linker Flags ---
LDFLAGS = -Lthird_party/onnxruntime/lib -lssl -lcrypto -lpthread -lonnxruntime

RPATH_LDFLAGS = -Wl,-rpath,'$$ORIGIN/../third_party/onnxruntime/lib'

# Directories
SRCDIR = src
BINDIR = bin

# Find all .cpp files in SRCDIR
SOURCES = $(shell find $(SRCDIR) -name '*.cpp')

# --- Release Target ---
TARGET = $(BINDIR)/anomaly_detector
OBJDIR_RELEASE = obj_release
OBJECTS_RELEASE = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR_RELEASE)/%.o,$(SOURCES))

all: $(TARGET)

$(TARGET): $(OBJECTS_RELEASE)
	@mkdir -p $(BINDIR)
	$(CXX) $(RELEASE_CXXFLAGS) $^ -o $@ $(LDFLAGS) $(RPATH_LDFLAGS)
	@echo "Built $(TARGET) successfully."

$(OBJDIR_RELEASE)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(RELEASE_CXXFLAGS) -c $< -o $@


# --- Debug Target ---
DEBUG_TARGET = $(BINDIR)/anomaly_detector_debug
OBJDIR_DEBUG = obj_debug
OBJECTS_DEBUG = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR_DEBUG)/%.o,$(SOURCES))

debug: $(OBJECTS_DEBUG)
	@mkdir -p $(BINDIR)
	$(CXX) $(DEBUG_CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $(DEBUG_TARGET) successfully."

$(OBJDIR_DEBUG)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(DEBUG_CXXFLAGS) -c $< -o $@


# --- Phony Targets ---
.PHONY: clean all debug run build

# Clean up build files
clean:
	rm -rf $(OBJDIR_RELEASE) $(OBJDIR_DEBUG) $(BINDIR)
	@echo "Cleaned build artifacts."

# Run the program with a default config file
run: all
	@echo "Running anomaly_detector with default config.ini..."
	./$(TARGET) config.ini

# Command to simply compile without running
build: all