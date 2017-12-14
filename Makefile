CPPFLAGS=-g -std=c++11 -pthread -Wall
LDFLAGS=-g
LDLIBS=-lssl -lcrypto

TARGET=main
SRC_DIRS ?= ./

SRCS=$(shell find $(SRC_DIRS) -name "*.cpp" -or -name "*.c" -or -name "*.s")
OBJS=$(subst .cpp,.o,$(SRCS))


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS) 

%.o: %.cpp
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $<

clean:
	$(RM) $(OBJS)

dist-clean: clean
	$(RM) $(TARGET)
