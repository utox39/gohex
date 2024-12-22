GO_BIN = gohex
CXX = g++
CXXFLAGS = -std=c++11 -shared -fPIC
LDFLAGS = -lcapstone -lLIEF
LIB_DIR = /usr/lib
BIN_DIR = /usr/local/bin
LIB_NAME = libgohexdisassembler.so
LIB_SRC = disassembler/disassembler_wrapper.cpp disassembler/disassembler.cpp

all: clean build build-disassembler

build: build-disassembler
	go build -o ./build/$(GO_BIN) main.go tui.go hex.go disassembler.go

build-disassembler:
	$(CXX) $(CXXFLAGS) -o ./build/$(LIB_NAME) $(LIB_SRC) $(LDFLAGS)

install:
	sudo cp ./build/$(LIB_NAME) $(LIB_DIR)
	sudo ldconfig
	sudo cp ./build/$(GO_BIN) $(BIN_DIR)

clean:
	rm -f ./build/$(GO_BIN) ./build/$(LIB_NAME)