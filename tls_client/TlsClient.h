#pragma once
#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <openssl/ssl.h>
#include <netinet/in.h>

#if OPENSSL_VERSION_NUMBER < 0x1010006f
	#error "require openssl lib >= 1.1.0f"
#endif

#ifndef HOST_NAME_MAX
	#define HOST_NAME_MAX 64
#endif

#ifdef PORT_MAX
	#error "redefinition of PORT_MAX"
#endif

#define PORT_MAX 10

typedef struct errinfo_t ErrInfo;

typedef struct {
	char hostname[HOST_NAME_MAX+1];
	char port[PORT_MAX+1];
	char ip[INET_ADDRSTRLEN+1];
} HostInfo;

typedef struct {
	SSL_CTX    *ctx;
	SSL	   *ssl;
	X509	   *cert;
	HostInfo   *hsinfo;
	ErrInfo    *errinfo;
	int	   tcp_sk;
} TlsClient;

TlsClient * TlsClient_new(const char *hostname, const char *port);
bool TlsClient_loadCA(TlsClient *cl, const char *ca);
bool TlsClient_doHandShake(TlsClient *cl, int sk);
const char * TlsClient_getError(TlsClient *cl);
void TlsClient_free(TlsClient *cl);