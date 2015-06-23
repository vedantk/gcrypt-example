LDFLAGS = -lgcrypt
CXXFLAGS = -std=c++11 -Wall -Wextra -g

BINS = keygen main
OBJS = gcry.o

all: $(BINS)

keygen: gcry.o
	$(CXX) $(CXXFLAGS) keygen.cc $(OBJS) -o keygen $(LDFLAGS)

main: gcry.o
	$(CXX) $(CXXFLAGS) main.cc $(OBJS) -o main $(LDFLAGS)

gcry.o: gcry.cc

clean:
	rm -f *.o $(BINS)
