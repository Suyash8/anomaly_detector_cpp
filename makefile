# Compiler and flags
CXX = g++
# C++17 for std::optional, std::from_chars, etc.
# -Isrc allows #include "header.hpp" from .cpp files in src/
# -Wall -Wextra -pedantic for more warnings
# -O3 for optimization
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -Isrc -O3
LDFLAGS = -lstdc++fs

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin
TESTDIR = tests

# Target executable
TARGET = $(BINDIR)/anomaly_detector

# Find all .cpp files in SRCDIR that are NOT main.cpp
LIB_SOURCES = $(filter-out $(SRCDIR)/main.cpp, $(shell find $(SRCDIR) -name '*.cpp'))
# Create object file paths for these "library" objects
LIB_OBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(LIB_SOURCES))

# Main executable source and object
MAIN_SOURCE = $(SRCDIR)/main.cpp
MAIN_OBJECT = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(MAIN_SOURCE))

# Default target: build all
all: $(TARGET)

# Rule to link the main target executable
$(TARGET): $(MAIN_OBJECT) $(LIB_OBJECTS)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $(TARGET) successfully."

# Rule to compile .cpp files into .o object files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Phony targets
.PHONY: clean all run build test-%

test-%: $(LIB_OBJECTS)
	@echo "--- Building and Running Test: test-$* ---"
	@mkdir -p $(BINDIR)
	# This command explicitly lists the test source file and the library objects
	$(CXX) $(CXXFLAGS) -o $(BINDIR)/test-$* $(TESTDIR)/test_$(subst -,_,$*).cpp $^ $(LDFLAGS)
	./$(BINDIR)/test-$*


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