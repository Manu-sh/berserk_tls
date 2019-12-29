CFLAGS=-std=c11 -O3 -Wall -Wextra -funroll-loops -ffast-math -pipe -pedantic #-fstack-protector-all
CXXFLAGS=$(CFLAGS)
LDLIBS=`pkg-config --libs openssl libcrypto`

.PHONY: all clean

all: main.c
	$(CC) -o main main.c $(LDLIBS) $(CFLAGS)

clean:
	rm -f main
