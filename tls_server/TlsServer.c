#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include "tls_server.h"
#include "tcp_server.h"
#include "TlsServer.h"

#define BACKLOG 5

// the main context
struct tls_server_t {
	SSL_CTX *ctx;
	int sk_listen;
};

TlsServer * TlsServer_new(int port, const char *key_file, const char *crt_file) {

	tls_lib_init();
	TlsServer *tls = calloc(1, sizeof(TlsServer));
	assert(tls);

	// listen socket
	if ((tls->sk_listen = tcp_server_listen_open(port, BACKLOG)) < 0) {
		free(tls);
		return NULL;
	}

	// load private key & public key
	if (!(tls->ctx = tls_server_ctx_new(key_file, crt_file))) {
		close(tls->sk_listen);
		free(tls);
		return NULL;
	}

	return tls;
}

TlsConnection * TlsServer_accept(TlsServer *tls) {

	// plain tcp socket
	const int client = tcp_server_accept_open(tls->sk_listen);
	if (client < 0) return NULL;

	char *ipv4 = NULL;

	{ // get ip
		struct sockaddr_in addr;
		socklen_t len = sizeof addr;
		getpeername(client, (struct sockaddr * )&addr, &len);

		// ipv4 only, however the listen socket only listen for ipv4 connection, so it's useless
		assert(addr.sin_family == AF_INET); 

		ipv4 = strdup(inet_ntoa(addr.sin_addr));
		fprintf(stderr, "[%s] connect\n", ipv4);
	}

	// secure tcp socket
	SSL *ssl = tls_server_tcp_secure_open(client, tls->ctx);
	if (!ssl) {
		free(ipv4);
		return NULL;
	}

	// lazy memory allocation
	TlsConnection *conn = calloc(1, sizeof(TlsConnection));
	assert(conn);

	conn->ssl = ssl;
	conn->sk_accept = client;
	conn->ip = ipv4;

	return conn;
}

void TlsServer_disconnect(TlsConnection *conn) {

	assert(conn);
	fprintf(stderr, "[%s] disconnect\n", conn->ip);

	tls_server_tcp_secure_close(conn->sk_accept, conn->ssl);
	free(conn->ip);
	free(conn);
}

void TlsServer_free(TlsServer *tls) {

	if (!tls) return;

	if (tls->ctx)
		tls_server_ctx_free(tls->ctx);

	if (tls->sk_listen >= 0)
		tcp_server_listen_close(tls->sk_listen);

	free(tls);
	tls_lib_cleanup();
}
