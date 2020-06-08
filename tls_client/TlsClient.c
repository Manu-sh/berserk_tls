#include "TlsClient.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/opensslv.h>

#if defined(EBSIZE)
	#error "redefinition of EBSIZE"
#elif defined(VFY_DEPTH)
#	error "redefinition of VFY_DEPTH"
#endif

#define ERR_GET_STR() ERR_reason_error_string(ERR_peek_error())
#define VFY_DEPTH 10
#define EBSIZE 4096

extern int errno, h_errno;
struct errinfo_t { char ebuf[EBSIZE]; };



// some helper
static void seterr(TlsClient *cl, const char *fname, const char *msg) {

	if (!cl || !cl->errinfo) return;

	if (!fname && msg)
		snprintf(cl->errinfo->ebuf, EBSIZE, "%s", msg);

	if (fname && msg)
		snprintf(cl->errinfo->ebuf, EBSIZE, "%s %s", fname, msg);

	if ((fname && !msg) || (!fname && !msg))
		seterr(cl, "Internal error seterr():", "invalid arguments");
}

static bool hostres(TlsClient *cl) {

	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sk;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family   = AF_INET;    /* AF_UNSPEC Allow IPv4 and IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	for (int ret = getaddrinfo(cl->hsinfo->hostname, cl->hsinfo->port, &hints, &result); ret != 0;) {
		seterr(cl, "getaddrinfo(): ", gai_strerror(ret));
		return false;
	}

	/* getaddrinfo() returns a list of address structures. Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (((sk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) != -1) && connect(sk, rp->ai_addr, rp->ai_addrlen) != -1) {

			/* In memory, the struct sockaddr_in and struct sockaddr_in6 share the same beginning structure as struct sockaddr, 
			and you can freely cast the pointer of one type to the other without any harm, except the possible end of the universe.
			http://beej.us/guide/bgnet/output/html/multipage/sockaddr_inman.html */

			struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
			strncpy(cl->hsinfo->ip, inet_ntoa(ipv4->sin_addr), INET_ADDRSTRLEN); // see note *1

			close(sk);
			freeaddrinfo(result);
			return true;	
		}

		close(sk);
	}


	freeaddrinfo(result);
	return false;
}

static bool TlsClient_doTcp(TlsClient *cl) {

	if (!hostres(cl)) {
		seterr(cl, "hostres():", "Unknown host");
		return false;
	}

	struct sockaddr_in sockdata;
	memset(&sockdata, 0, sizeof(struct sockaddr_in));

	sockdata.sin_port = htons((uint16_t)atoi(cl->hsinfo->port));
	sockdata.sin_family = AF_INET;

	if ((cl->tcp_sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		seterr(cl, "socket(): ", gai_strerror(h_errno));
		return false;
	}


	if (inet_pton(AF_INET, cl->hsinfo->ip, &sockdata.sin_addr) != 1) {
		seterr(cl, "inet_pton(): ", strerror(errno));
		return false;
	}

	if (connect(cl->tcp_sk, (struct sockaddr *)&sockdata, sizeof(sockdata)) < 0) {
		seterr(cl, "connect(): ", strerror(errno));
		return false;
	}

	return true;
}

#if 0
static const char * crt_strerror(int err) {

	switch(err) {

		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			return "UNABLE_TO_DECRYPT_CERT_SIGNATURE";

		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			return "UNABLE_TO_DECRYPT_CRL_SIGNATURE";

		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			return "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";

		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			return "CERT_SIGNATURE_FAILURE";

		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			return "CRL_SIGNATURE_FAILURE";

		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			return "ERROR_IN_CERT_NOT_BEFORE_FIELD";

		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			return "ERROR_IN_CERT_NOT_AFTER_FIELD";

		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			return "ERROR_IN_CRL_LAST_UPDATE_FIELD";

		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			return "ERROR_IN_CRL_NEXT_UPDATE_FIELD";

		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "CERT_NOT_YET_VALID";

		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "CERT_HAS_EXPIRED";

		case X509_V_ERR_OUT_OF_MEM:
			return "OUT_OF_MEM";

		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			return "UNABLE_TO_GET_ISSUER_CERT";

		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "UNABLE_TO_GET_ISSUER_CERT_LOCALLY";

		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "UNABLE_TO_VERIFY_LEAF_SIGNATURE";

		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return "DEPTH_ZERO_SELF_SIGNED_CERT";

		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "SELF_SIGNED_CERT_IN_CHAIN";

		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "CERT_CHAIN_TOO_LONG";

		case X509_V_ERR_CERT_REVOKED:
			return "CERT_REVOKED";

		case X509_V_ERR_INVALID_CA:
			return "INVALID_CA";

		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "PATH_LENGTH_EXCEEDED";

		case X509_V_ERR_INVALID_PURPOSE:
			return "INVALID_PURPOSE";

		case X509_V_ERR_CERT_UNTRUSTED:
			return "CERT_UNTRUSTED";

		case X509_V_ERR_CERT_REJECTED:
			return "CERT_REJECTED";

		case X509_V_ERR_UNABLE_TO_GET_CRL:
			return "UNABLE_TO_GET_CRL";

		case X509_V_ERR_CRL_NOT_YET_VALID:
			return "CRL_NOT_YET_VALID";

		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "CRL_HAS_EXPIRED";

	}

	return "Unknown verify error";
}
#endif



/* Initialization: this return a new Tls Client structure, or null in case of insuccess */
TlsClient * TlsClient_new(const char *hostname, const char *port) {

	TlsClient *cl;

	if (!hostname || !port || strcmp(port, "") == 0 || !(cl = (TlsClient *)calloc(1, sizeof(TlsClient)))) 
		return NULL;

	if (!(cl->hsinfo = (HostInfo *)calloc(1, sizeof(HostInfo)))) {
		free(cl);
		return NULL;
	}

	if (!(cl->errinfo = (ErrInfo *)calloc(1, sizeof(ErrInfo)))) {
		free(cl->hsinfo);
		free(cl);
		return NULL;
	}

	strncpy(cl->hsinfo->hostname, hostname, HOST_NAME_MAX);
	strncpy(cl->hsinfo->port, port, PORT_MAX);
	cl->tcp_sk = -1;

	if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL)) {
		free(cl->hsinfo);
		free(cl->errinfo);
		free(cl);
		return NULL;
	}

	if (!(cl->ctx = SSL_CTX_new(TLS_client_method()))) {
		free(cl->hsinfo);
		free(cl->errinfo);
		free(cl);
		return NULL;
	}

	SSL_CTX_set_verify(cl->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(cl->ctx, VFY_DEPTH);

	// exclude old protocol version
	SSL_CTX_set_min_proto_version(cl->ctx, TLS1_VERSION);
	SSL_CTX_set_max_proto_version(cl->ctx, TLS1_3_VERSION);

	// TODO create my own callback ?
	// SSL_CTX_set_cert_verify_callback(cl->ctx, NULL, NULL);

	return cl;
}

bool TlsClient_loadKeys(TlsClient *cl, const char *crt, const char *key) {

	if (SSL_CTX_use_certificate_file(cl->ctx, crt, SSL_FILETYPE_PEM) <= 0) {
		seterr(cl, "SSL_CTX_use_certificate_file(): ", crt);
		return false;
	}

	if (SSL_CTX_use_PrivateKey_file(cl->ctx, key, SSL_FILETYPE_PEM) <= 0) {
		seterr(cl, "SSL_CTX_use_PrivateKey_file(): ", key);
		return false;
	}

	return true;
}

// set CA file or folder for crt validation sent by the host, two default value CA_FILE, and CA_CERT (should be renamed)
// are defined into TlsClient.h
bool TlsClient_loadCA(TlsClient *cl, const char *ca) {

	if (!cl || !ca || strcmp(ca, "") == 0) {
		seterr(cl, "TlsClient_loadCA(): ", "Invalid arguments");
		return false;
	}

	int fd = open(ca, O_RDONLY|O_NONBLOCK);
	struct stat status;

	if (fd == -1) {
		seterr(cl, "open(): ", strerror(errno));
		return false;
	}

	if (fstat(fd, &status) != 0) {
		seterr(cl, "fstat(): ", strerror(errno));
		goto fail;
	}

	switch (status.st_mode & S_IFMT) {
		case S_IFREG:
			SSL_CTX_set_verify_depth(cl->ctx, VFY_DEPTH);
			if ((SSL_CTX_load_verify_locations(cl->ctx, ca, NULL)) != 1) {
				seterr(cl, "SSL_CTX_load_verify_locations():", "load ca from file: failure");
				goto fail;
			}
			break;
		case S_IFDIR:
			if ((SSL_CTX_load_verify_locations(cl->ctx, NULL, ca)) != 1) {
				seterr(cl, "SSL_CTX_load_verify_locations():", "load ca from path: failure");
				goto fail;
			}
			break;
		default:
			seterr(cl, "SslClient_loadCA(): ", "the ca argument must to be a directory path or a regular file");
			goto fail;
	}

	close(fd);
	return true;

fail:
	close(fd);
	return false;
}

// provide an existing tcp socket to use or -1
bool TlsClient_doHandShake(TlsClient *cl, int sk) {

	if ((cl->tcp_sk = sk) == -1 && !TlsClient_doTcp(cl))
		return false;

	if (!(cl->ssl = SSL_new(cl->ctx))) {
		seterr(cl, "SSL_new(): ", ERR_GET_STR());
		return false;
	}

	if (SSL_set_fd(cl->ssl, cl->tcp_sk) != 1) {
		seterr(cl, "SSL_set_fd(): ", ERR_GET_STR());
		return false;
	}

	SSL_set_mode(cl->ssl, SSL_MODE_AUTO_RETRY);

	// SSL_connect() == SSL_set_connect_state(cl->ssl) (required for setting ssl handshake in client mode) + SSL_do_handshake()
	if (SSL_connect(cl->ssl) != 1) {
		seterr(cl, "SSL_connect(): ", ERR_GET_STR());
		return false;
	}

	if (!(cl->cert = SSL_get_peer_certificate(cl->ssl))) {
		seterr(cl, "SSL_get_peer_certificate(): ", "no crt presented");
		return false;
	}

	return true;

}

const char * TlsClient_getError(TlsClient *cl) { 
	return cl->errinfo->ebuf;
}


void TlsClient_free(TlsClient *cl) {
	if (!cl) return;

	if (cl->tcp_sk != -1) {

		while (!SSL_shutdown(cl->ssl)) {
			fprintf(stdout, "shutting down\n");
			sleep(1);
		}

		// shutdown(cl->tcp_sk, SHUT_RDWR);
		close(cl->tcp_sk);
	}

	SSL_free(cl->ssl);
	SSL_CTX_free(cl->ctx);
	X509_free(cl->cert);
	free(cl->hsinfo);
	free(cl->errinfo);
	free(cl);
}