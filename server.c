#include "tls_server/TlsServer.h"
#include <stdlib.h>
#include <string.h>

// TO TEST:
// openssl s_client -connect localhost:5000 -tls1 -key key.pem

int main() {

	TlsServer *instance = TlsServer_new(5000, "key.pem", "crt.pem");

	while (1) { // Handle connections

		TlsConnection *client = TlsServer_accept(instance);
		if (!client) continue;

#if 0
		SSL_write(client->ssl, "test server\n", strlen("test server\n"));

		char buf[16 * 1001];
		for (int len; (len = SSL_read(client->ssl, buf, sizeof buf)) > 0;)
			fprintf(stdout, "%.*s %d", len, buf, len);
#endif

		unsigned char buf;
		SSL_read(client->ssl, &buf, sizeof buf);
		if (buf == '\33') 
			puts("LED ON");
		else
			puts("LED OFF");

		TlsServer_disconnect(client);

	}

	TlsServer_free(instance);
	return EXIT_SUCCESS;
}
