#include "tls_client/TlsClient.h"

int main() {

	TlsClient *client;

	if (!(client = TlsClient_new("localhost", "5000"))) {
		fprintf(stderr, "err init\n");
		return EXIT_FAILURE;
	}

	if (!TlsClient_loadCA(client, "crt.pem"))
		goto failure;

	if (!TlsClient_doHandShake(client, -1))
		goto failure;

	printf("%s [OK]\n", client->hsinfo->hostname);
	TlsClient_free(client);
	return EXIT_SUCCESS;

failure:
	printf("%s [BAD]\n", client->hsinfo->hostname);
	printf("error: %s\n", TlsClient_getError(client));
	TlsClient_free(client);
	return EXIT_FAILURE;

}
