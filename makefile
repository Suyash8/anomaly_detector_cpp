# Compiler and flags
CXX = g++
# C++17 for std::optional, std::from_chars, etc.
# -Isrc allows #include "header.hpp" from .cpp files in src/
# -Wall -Wextra -pedantic for more warnings
# -O3 for optimization
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -Isrc -Ithird_party/cpp-httplib -DCPPHTTPLIB_OPENSSL_SUPPORT -O3
LDFLAGS = -lssl -lcrypto -lpthread

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin

# Target executable
TARGET = $(BINDIR)/anomaly_detector

# Find all .cpp files in SRCDIR
SOURCES = $(shell find $(SRCDIR) -name '*.cpp')
# Create object file paths: replace src/%.cpp with obj/%.o
OBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SOURCES))

# Default target: build all
all: $(TARGET)

# Rule to link the target executable
$(TARGET): $(OBJECTS)
	@mkdir -p $(BINDIR) # Create bin directory if it doesn't exist
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@ # $^ is all prerequisites (OBJECTS), $@ is the target
	@echo "Built $(TARGET) successfully."

# Rule to compile .cpp files into .o object files
# $< is the first prerequisite (the .cpp file)
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(@D) # Create obj directory if it doesn't exist
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $< -o $@

# Phony targets (targets that don't represent files)
.PHONY: clean all run

# Clean up build files
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "Cleaned build artifacts."

# Run the program with a default config file (if main takes it as an arg)
run: all
	@echo "Running anomaly_detector with default config.ini..."
	./$(TARGET) config.ini

# Command to simply compile without running
build: all