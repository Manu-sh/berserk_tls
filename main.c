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

		char buf[16 * 1001];
		for (int len; (len = SSL_read(client->ssl, buf, sizeof buf)) > 0;)
			fprintf(stdout, "%.*s %d", len, buf, len);

		TlsServer_disconnect(client);

	}

	TlsServer_free(tls);
}
