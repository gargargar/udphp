#
# A simple makefile for compiling a c++ project
#
SRC=./src
TARGET=./out
GCC = g++
CFLAGS = -o $(TARGET)/udphp_client -std=c++20 -Wall -I ../include -luuid
#ARGS = 101
RM = rm -rf

all: clean build# test

build: main.cpp

main.cpp:
	mkdir -p $(TARGET)
	$(GCC) $(SRC)/main.cpp $(CFLAGS)

# test: main.cpp
#     $(TARGET)/test_raw $(ARGS)

clean:
	$(RM) $(TARGET)/*.o