# A simple makefile for compiling a c++ project
SRCDIR = ./src
TARGETDIR = ./out
TARGETNAME = udphp-server
CXX = g++
CXXFLAGS += -std=c++20 -Wall -O2 -I ../include
LDFLAGS += -luuid -static

OBJS = $(patsubst $(SRCDIR)/%.cpp,$(TARGETDIR)/%.o,$(wildcard $(SRCDIR)/*.cpp))

all: $(TARGETDIR) $(TARGETDIR)/$(TARGETNAME)

$(TARGETDIR):
	mkdir -p $(TARGETDIR)

$(TARGETDIR)/$(TARGETNAME): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

$(TARGETDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

clean:
	rm -f $(TARGETDIR)/*.o $(TARGETDIR)/$(TARGETNAME)