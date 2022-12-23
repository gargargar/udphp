#
# A simple makefile for compiling a c++ project
#
SRC=./src
TARGET=./out
GCC = g++
CFLAGS = -o $(TARGET)/udphp_server -std=c++20 -Wall -fdiagnostics-color=always \
	-I ../include -O2
#ARGS = 101
RM = rm -rf

all: clean build# test

build: main.cpp

main.cpp:
	$(GCC) $(CFLAGS) $(SRC)/main.cpp

# test: main.cpp
#     $(TARGET)/test_raw $(ARGS)

clean:
	$(RM) $(TARGET)/*