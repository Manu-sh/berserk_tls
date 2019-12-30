CFLAGS=-O3 -pipe -Wall -Wextra -Wno-unused-function -pedantic -std=c11
LDLIBS=`pkg-config --libs openssl libcrypto`
libtlss=libtlss

.PHONY: clean all

all: $(libtlss).a

$(libtlss).a: TlsServer.c TlsServer.h
	$(CC)  -c TlsServer.c $(CFLAGS)
	$(AR) rcs $(libtlss).a TlsServer.o

clean:
	rm -fv *.o *.a
