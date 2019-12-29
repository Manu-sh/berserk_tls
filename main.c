#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


// #define LOG(_E_MSG_) (syslog(1, __FILE__ " %s", _E_MSG_))
#define LOG(_E_MSG_) (perror(_E_MSG_))

// TO TEST:
// openssl s_client -connect localhost:5000 -tls1 -key key.pem

// onerror: -1
int tls_tcp_socket_new(int port) {

	int sk = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family      = AF_INET,
		.sin_port        = htons(port),
		.sin_addr.s_addr = htonl(INADDR_ANY)
	};

	if (sk < 0) {
		LOG("Unable to create socket");
		return -1;
	}

	if (bind(sk, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(sk);
		LOG("Unable to bind");
		return -1;
	}

	if (listen(sk, 1) < 0) {
		close(sk);
		LOG("Unable to listen");
		return -1;
	}

	return sk;
}

void tls_init() {
	assert(OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL));
}

void tls_cleanup() {
	OPENSSL_cleanup();
}

// onerror: NULL
SSL_CTX * tls_ctx_new() {

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

	if (!ctx) {
		LOG("Unable to create SSL context");
		LOG(ERR_reason_error_string(ERR_peek_last_error()));
		return NULL;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);

	// exclude old protocol version
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		LOG(ERR_reason_error_string(ERR_peek_last_error()));
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
		LOG(ERR_reason_error_string(ERR_peek_last_error()));
		return NULL;
	}

	return ctx;
}

int main() {

	tls_init();
	SSL_CTX *ctx = tls_ctx_new();

	int sock = tls_tcp_socket_new(5000);

	/* Handle connections */
	while(1) {

		struct sockaddr_in addr;
		uint len = sizeof(addr);
		const char reply[] = "test\n";

		int client = accept(sock, (struct sockaddr*)&addr, &len);
		if (client < 0) {
			LOG("Unable to accept");
			exit(EXIT_FAILURE);
		}

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) <= 0)
			LOG(ERR_reason_error_string(ERR_peek_last_error()));
		else
			SSL_write(ssl, reply, strlen(reply));

		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client);
	}

	close(sock);
	SSL_CTX_free(ctx);
	tls_cleanup();
}


