CXX = clang++
LDFLAGS = -lgcrypt
CXXFLAGS = -std=c++11 -Wall -Wextra -g

BINS = keygen main

all: $(BINS)

gcry.o: gcry.cc gcry.hh
keygen: keygen.cc gcry.o
main: main.cc gcry.o

clean:
	rm -f *.o $(BINS)
