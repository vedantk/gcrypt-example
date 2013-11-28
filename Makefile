CXX = clang++
LDFLAGS = -lgcrypt
CXXFLAGS = -std=c++11 -Wall -Wextra -g

BINS = keygen main

all: $(BINS)

util.o: util.cc util.hh
gcry.o: gcry.cc gcry.hh
keygen: keygen.cc util.o gcry.o
main: main.cc util.o gcry.o

clean:
	rm -f *.o $(BINS)
