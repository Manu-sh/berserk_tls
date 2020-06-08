#pragma once
#include "log.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <unistd.h>

void tls_lib_init() { assert(OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL)); }
void tls_lib_cleanup() { OPENSSL_cleanup(); }

// onerror: NULL
SSL_CTX * tls_server_ctx_new(const char *file_pkey, const char *file_crt) {

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

	if (!ctx) {
		LOG(stderr, "Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);

	// exclude old protocol version
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

	// load the CA (from file) see also: TlsClient_loadCA()
	if ((SSL_CTX_load_verify_locations(ctx, file_crt, NULL)) != 1) {
		LOG(stderr, "Unable to load CA file into SSL context");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	// Set the key and cert
	if (SSL_CTX_use_certificate_file(ctx, file_crt, SSL_FILETYPE_PEM) <= 0) {
		LOG(stderr, "Unable to load CRT file into SSL context");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, file_pkey, SSL_FILETYPE_PEM) <= 0) {
		LOG(stderr, "Unable to load KEY file into SSL context");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

#if 0
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(file_crt));
#endif

	return ctx;
}

void tls_server_ctx_free(SSL_CTX *ctx) {
	SSL_CTX_free(ctx);
}

// in case of failure you must close sk_client by yourself
SSL * tls_server_tcp_secure_open(int sk_client, SSL_CTX *ctx) {

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sk_client);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);

		if (sk_client >= 0)
			close(sk_client);

		return NULL;
	}

	return ssl;
}

// this also close sk_client
void tls_server_tcp_secure_close(int sk_client, SSL *ssl) {

	if (ssl) {

		while (!SSL_shutdown(ssl)) {
			LOG(stdout, "shutting down");
			sleep(1);
		}

		SSL_free(ssl);
	}

	if (sk_client >= 0)
		close(sk_client);
}