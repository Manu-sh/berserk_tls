#pragma once
#include <openssl/ssl.h>

typedef struct tls_server_t TlsServer;

// an incoming connection
typedef struct {

	SSL *ssl;
	int sk_accept;

	struct {
		char *ip;
	};

} TlsConnection;

TlsServer * TlsServer_new(int port, const char *key_file, const char *crt_file);
TlsConnection * TlsServer_accept(TlsServer *tls);
void TlsServer_disconnect(TlsConnection *conn);
void TlsServer_free(TlsServer *tls);