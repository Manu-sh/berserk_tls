#include "tls_client/TlsClient.h"
#include <string.h>

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

#if 0
	SSL_write(instance->ssl, "test client\n", strlen("test client\n"));

	char buf[16 * 1001];
	for (int len; (len = SSL_read(instance->ssl, buf, sizeof buf)) > 0;)
		fprintf(stdout, "%.*s %d", len, buf, len);
#endif


	unsigned char buf = '\33';
	SSL_write(instance->ssl, &buf, sizeof buf);


	TlsClient_free(instance);
	return EXIT_SUCCESS;

failure:
	printf("%s [BAD]\n", instance->hsinfo->hostname);
	printf("error: %s\n", TlsClient_getError(instance));
	TlsClient_free(instance);
	return EXIT_FAILURE;

}
