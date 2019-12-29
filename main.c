#include "include/tls.h"

#include <assert.h>
#include <string.h>

// TO TEST:
// openssl s_client -connect localhost:5000 -tls1 -key key.pem

int main() {

	tls_lib_init();
	SSL_CTX *ctx = tls_ctx_new("key.pem", "cert.pem");
	int sock = tcp_listen_open(5000, 1);

	// Handle connections
	while(1) {

		int client = tcp_accept_open(sock);
		if (client < 0)
            continue;

		SSL *ssl = tls_tcp_secure_open(client, ctx);
		if (!ssl) {
		    tcp_accept_close(client);
            continue;
		}

		SSL_write(ssl, "test\n", strlen("test\n"));
        tls_tcp_secure_close(client, ssl);
	}

    tcp_listen_close(sock);
	tls_ctx_free(ctx);
	tls_lib_cleanup();
}