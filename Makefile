# ============ Compiler & Common Flags ============
CXX = g++
CXXFLAGS = -Wall -std=c++20 -Iinclude

# OpenSSL and system libs
OPENSSL_LIBS = -lssl -lcrypto -lws2_32 -lcrypt32
MINGW_LIBDIR = -L"C:/msys64/mingw64/lib"

# ============ FRONTEND (main.exe) ============

FRONTEND_SRC_DIR = src/frontend
FRONTEND_OBJ_DIR = obj/frontend
FRONTEND_SRCS = $(wildcard $(FRONTEND_SRC_DIR)/*.cpp)
FRONTEND_OBJS = $(patsubst $(FRONTEND_SRC_DIR)/%.cpp, $(FRONTEND_OBJ_DIR)/%.o, $(FRONTEND_SRCS))
FRONTEND_CXXFLAGS = $(CXXFLAGS) -Iinclude/frontend
FRONTEND_LDFLAGS = $(MINGW_LIBDIR) $(OPENSSL_LIBS) -static

main.exe: $(FRONTEND_OBJS)
	$(CXX) $^ -o $@ $(FRONTEND_CXXFLAGS) $(FRONTEND_LDFLAGS)

$(FRONTEND_OBJ_DIR)/%.o: $(FRONTEND_SRC_DIR)/%.cpp
	@mkdir -p $(FRONTEND_OBJ_DIR)
	$(CXX) -c $< -o $@ $(FRONTEND_CXXFLAGS)

# ============ STUB (out/stub.exe) ============

# Match one stub_*.cpp file in /stub
STUB_GENERATED_CPP := $(firstword $(wildcard stub/stub_*.cpp))
STUB_SRC_DIR = src/stub
STUB_OBJ_DIR = obj/stub
STUB_SRCS = $(wildcard $(STUB_SRC_DIR)/*.cpp)
STUB_SRCS += $(STUB_GENERATED_CPP)
STUB_OBJS = $(patsubst %.cpp, $(STUB_OBJ_DIR)/%.o, $(notdir $(STUB_SRCS)))
STUB_CXXFLAGS = $(CXXFLAGS) -Iinclude/stub
STUB_LDFLAGS = $(MINGW_LIBDIR) $(OPENSSL_LIBS) -lshlwapi -static

out/stub.exe: $(STUB_OBJS)
	$(CXX) $^ -o $@ $(STUB_CXXFLAGS) $(STUB_LDFLAGS)

$(STUB_OBJ_DIR)/%.o: $(STUB_SRC_DIR)/%.cpp
	@mkdir -p $(STUB_OBJ_DIR)
	$(CXX) -c $< -o $@ $(STUB_CXXFLAGS)

$(STUB_OBJ_DIR)/stub.o: stub/stub.cpp
	@mkdir -p $(STUB_OBJ_DIR)
	$(CXX) -c $< -o $@ $(STUB_CXXFLAGS)

# Handle stub/stub_*.cpp files
$(STUB_OBJ_DIR)/%.o: stub/%.cpp
	@mkdir -p $(STUB_OBJ_DIR)
	$(CXX) -c $< -o $@ $(STUB_CXXFLAGS)



# ============ PROCINJ (bin/procinj.exe) ============

PROJ_SRC = resource/procinj.cpp
PROJ_BIN = bin/procinj.exe

$(PROJ_BIN): $(PROJ_SRC)
	@mkdir -p bin
	$(CXX) -static-libgcc -static-libstdc++ -fexceptions -static -o $@ $<

# ============ Meta Targets ============

.PHONY: all clean

all: main.exe out/stub.exe $(PROJ_BIN)

clean:
	rm -rf obj/* out/* bin/* main.exe
