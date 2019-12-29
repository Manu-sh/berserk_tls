#include <string.h>
#include "include/tls_server.h"
#include "include/tcp_server.h"

// the main context
typedef struct {
    SSL_CTX *ctx;
    int sk_listen;
} TlsServer;

// an incoming connection
typedef struct {
    SSL *ssl;
    int sk_accept;
} TlsConnection;

#define PORT 5000
#define BACKLOG 5
#define CRT_FILE "crt.pem"
#define KEY_FILE "key.pem"

TlsServer * TlsServer_new() {

    tls_lib_init();
    TlsServer *tls = (TlsServer *)calloc(1, sizeof(TlsServer));
    assert(tls);

    // listen socket
    if ((tls->sk_listen = tcp_server_listen_open(PORT, BACKLOG)) < 0) {
        free(tls);
        return NULL;
    }

    // load private key & public key
    if (!(tls->ctx = tls_server_ctx_new(KEY_FILE, CRT_FILE))) {
        close(tls->sk_listen);
        free(tls);
        return NULL;
    }

    return tls;
}

TlsConnection * TlsServer_connect(TlsServer *tls) {

	// plain tcp socket
	int client = tcp_server_accept_open(tls->sk_listen);
	if (client < 0) return NULL;

	{
		struct sockaddr_in addr;
		socklen_t len = sizeof addr;
		getpeername(client, (struct sockaddr * )&addr, &len);

		// ipv4, however the listen socket only listen for ipv4 connection, so it's useless
		assert(addr.sin_family == AF_INET); 

		LOG(stderr, inet_ntoa(addr.sin_addr));
	}

	// secure tcp socket
	SSL *ssl = tls_server_tcp_secure_open(client, tls->ctx);
	if (!ssl)
		return NULL;

	// lazy memory allocation
	TlsConnection *conn = calloc(1, sizeof(TlsConnection));
	assert(conn);

	conn->ssl = ssl;
	conn->sk_accept = client;

	return conn;
}

void TlsServer_disconnect(TlsConnection *conn) {
	assert(conn);
	tls_server_tcp_secure_close(conn->sk_accept, conn->ssl);
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


// TO TEST:
// openssl s_client -connect localhost:5000 -tls1 -key key.pem

int main() {

	TlsServer *tls = TlsServer_new();

	// Handle connections
	while(1) {

		TlsConnection *client = TlsServer_connect(tls);
		if (!client) continue;

		SSL_write(client->ssl, "test\n", strlen("test\n"));
		TlsServer_disconnect(client);

	}

	TlsServer_free(tls);
}
