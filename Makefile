CFLAGS=-std=c11 -O3 -Wall -Wextra -funroll-loops -ffast-math -pipe -pedantic -Wno-unused-function #-fstack-protector-all
CXXFLAGS=$(CFLAGS)
LDLIBS=`pkg-config --libs openssl libcrypto`

.PHONY: all clean

all: server.c client.c
	make -C tls_client
	$(CC) -o client client.c $(LDLIBS) $(CFLAGS) tls_client/libtlsc.a
	$(CC) -o server server.c $(LDLIBS) $(CFLAGS)

clean:
	rm -f main
