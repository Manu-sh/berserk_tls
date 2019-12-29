CFLAGS=-O3 -pipe -Wall -Wextra -Wno-unused-function -pedantic
CXXFLAGS=$(CFLAGS)
LDLIBS=`pkg-config --libs openssl libcrypto`

.PHONY: all clean

all: main.c
	$(CC) -o main main.c $(LDLIBS) $(CFLAGS)

clean:
	rm -fv main
