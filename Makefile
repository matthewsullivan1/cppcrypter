# Compiler and flags
CXX = g++
CXXFLAGS = -I"C:\Program Files\OpenSSL-Win64\include" -static-libgcc -static-libstdc++ -static
LDFLAGS = -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT" -lssl -lcrypto

# Flags for procinj.cpp
PROCINJ_FLAGS = -static-libgcc -static-libstdc++ -fexceptions

# Directories
BINDIR = bin
STUBDIR = stub

# Source files
MAIN_SRCS = main.cpp utils.cpp
PROJ_SRCS = procinj.cpp
STUB_SRCS = $(wildcard $(STUBDIR)/stub_*.cpp)

# Targets
TARGET_MAIN = main.exe
TARGET_PROJ = $(BINDIR)/procinj.exe
STUB_TARGETS = $(patsubst $(STUBDIR)/%.cpp,$(STUBDIR)/%,$(STUB_SRCS))

# Default target
all: $(TARGET_PROJ) $(TARGET_MAIN) $(STUB_TARGETS)

# Rule to build procinj
$(TARGET_PROJ): $(PROJ_SRCS) | $(BINDIR)
	$(CXX) $(PROCINJ_FLAGS) -o $@ $(PROJ_SRCS)

# Rule to build main
$(TARGET_MAIN): $(MAIN_SRCS)
	$(CXX) -o $@ $(MAIN_SRCS) $(CXXFLAGS) $(LDFLAGS)

# Rule to build each stub
$(STUBDIR)/%: $(STUBDIR)/%.cpp
	$(CXX) -o $@ $< $(CXXFLAGS) "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT\libssl.lib" "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT\libcrypto.lib"

# Target to build all stubs
stub: $(STUB_TARGETS)

# Rule to clean up object and executable files
clean:
	del /Q $(BINDIR)\*.exe $(TARGET_MAIN) $(STUBDIR)\stub_*.exe

.PHONY: all clean stub
