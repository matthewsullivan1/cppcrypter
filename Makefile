# Compiler and flags
CXX = g++
CXXFLAGS = -I"./include" -static-libgcc -static-libstdc++ -static
LDFLAGS = -L"./lib" "./lib/libssl.lib" "./lib/libcrypto.lib"

# Flags for procinj.cpp
PROCINJ_FLAGS = -static-libgcc -static-libstdc++ -fexceptions --static

# Directories
BINDIR = bin
STUBDIR = stub
OUTDIR = out
SRCDIR = src
RESDIR = resource

# Source files
MAIN_SRCS = $(SRCDIR)/main.cpp $(SRCDIR)/utils.cpp
PROJ_SRCS = $(RESDIR)/procinj.cpp
STUB_SRCS = $(wildcard $(STUBDIR)/stub_*.cpp)

# Targets
TARGET_MAIN = main.exe
TARGET_PROJ = $(BINDIR)/procinj.exe
STUB_TARGETS = $(patsubst $(STUBDIR)/stub_%.cpp,$(OUTDIR)/stub_%.exe,$(STUB_SRCS))

# Default target
all: $(TARGET_PROJ) $(TARGET_MAIN) stub

# Rule to build procinj
$(TARGET_PROJ): $(PROJ_SRCS) | $(BINDIR)
	$(CXX) $(PROCINJ_FLAGS) -o $@ $(PROJ_SRCS)

# Rule to build main
$(TARGET_MAIN): $(MAIN_SRCS)
	$(CXX) -o $@ $(MAIN_SRCS) $(CXXFLAGS) $(LDFLAGS)

# Rule to build each stub
$(OUTDIR)/stub_%.exe: $(STUBDIR)/stub_%.cpp | $(OUTDIR)
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS)

# Target to build all stubs
stub: $(STUB_TARGETS)

# Rule to clean up object and executable files
clean:
	rm $(TARGET_MAIN) $(STUB_SRCS) $(TARGET_PROJ) $(OUTDIR)/stub_*.exe
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
