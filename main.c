#include "include/TlsServer.h"

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
