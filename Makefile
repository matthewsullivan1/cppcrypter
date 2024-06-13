# Set compiler
CXX = g++

# Flags for g++ and LD
# Remove -s for easier binary analysis
# CXXFLAGS = -s -I"./include" -static-libgcc -static-libstdc++ -static
CXXFLAGS = -I"./include"
STUBFLAGS = -static-libstdc++ -static-libgcc --static
LDFLAGS = -L"./lib" "./lib/libssl.lib" "./lib/libcrypto.lib"

# g++ flags for payload
PL_FLAGS = -static-libgcc -static-libstdc++ -fexceptions --static

# Project directories
BINDIR = bin
STUBDIR = stub
OUTDIR = out
SRCDIR = src
RESDIR = resource

# Source files
MAIN_SRCS = $(SRCDIR)/main.cpp $(SRCDIR)/utils.cpp
PL_SRC = $(RESDIR)/procinj.cpp
STUB_SRCS = $(wildcard $(STUBDIR)/stub_*.cpp)

# Targets
TARGET_MAIN = main.exe
TARGET_PL = $(BINDIR)/procinj.exe
STUB_TARGETS = $(patsubst $(STUBDIR)/stub_%.cpp,$(OUTDIR)/stub_%.exe,$(STUB_SRCS))

# Default target
all: $(TARGET_PL) $(TARGET_MAIN) stub

# Rule to build payload
# make bin/procinj.exe
$(TARGET_PL): $(PL_SRC) | $(BINDIR)
	$(CXX) $(PL_FLAGS) -o $@ $(PL_SRC)

# Rule to build main
# make main.exe
$(TARGET_MAIN): $(MAIN_SRCS)
	$(CXX) -o $@ $(MAIN_SRCS) $(CXXFLAGS) $(LDFLAGS)

# Rule to build stubs individually
# make stub/stub_********.exe
$(OUTDIR)/stub_%.exe: $(STUBDIR)/stub_%.cpp | $(OUTDIR)
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS) $(STUBFLAGS)

# Target to build all stubs
# make stub
stub: $(STUB_TARGETS)

# Rule to clean up object and executable files
clean:
	rm $(TARGET_MAIN) $(STUB_SRCS) $(OUTDIR)/stub_*.exe
# Ensure the bin and out directories exist 
$(BINDIR):
	mkdir $(BINDIR)

$(OUTDIR):
	mkdir $(OUTDIR)

.PHONY: all clean stub print-%


# Print values of variables
print-STUB_SRCS:
	@echo STUB_SRCS: $(STUB_SRCS)

print-STUB_TARGETS:
	@echo STUB_TARGETS: $(STUB_TARGETS)
