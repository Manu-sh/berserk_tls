#include "tls_client/TlsClient.h"

int main() {

	TlsClient *instance;

	if (!(instance = TlsClient_new("localhost", "5000"))) {
		fprintf(stderr, "err init\n");
		return EXIT_FAILURE;
	}

	if (!TlsClient_loadCA(instance, "crt.pem"))
		goto failure;

	if (!TlsClient_doHandShake(instance, -1))
		goto failure;

	printf("%s [OK]\n", instance->hsinfo->hostname);
	TlsClient_free(instance);
	return EXIT_SUCCESS;

failure:
	printf("%s [BAD]\n", instance->hsinfo->hostname);
	printf("error: %s\n", TlsClient_getError(instance));
	TlsClient_free(instance);
	return EXIT_FAILURE;

}
