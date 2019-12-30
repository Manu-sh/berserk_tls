CFLAGS=-std=c11 -O3 -Wall -Wextra -funroll-loops -ffast-math -pipe -pedantic #-fstack-protector-all
CXXFLAGS=$(CFLAGS)
LDLIBS=`pkg-config --libs openssl libcrypto`

.PHONY: all clean

all: server.c client.c
	make -C tls_client
	make -C tls_server

	$(CC) -o client client.c $(LDLIBS) $(CFLAGS) tls_client/libtlsc.a
	$(CC) -o server server.c $(LDLIBS) $(CFLAGS) tls_server/libtlss.a

clean:
	rm -f client server tls_{client,server}/*.{o,a}
