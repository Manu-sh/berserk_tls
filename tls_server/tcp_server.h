#pragma once
#include "log.h"

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// onerror: -1
int tcp_server_listen_open(int port, int backlog) {

	const int sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in addr = {
		.sin_family      = AF_INET, // ipv4 only
		.sin_port        = htons(port),
		.sin_addr.s_addr = htonl(INADDR_ANY)
	};

	if (sk < 0) {
		LOG(stderr, "Unable to create socket");
		return -1;
	}

	if (bind(sk, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(sk);
		LOG(stderr, "Unable to bind");
		return -1;
	}

	if (listen(sk, backlog) < 0) {
		close(sk);
		LOG(stderr, "Unable to listen");
		return -1;
	}

	return sk;
}

void tcp_server_listen_close(int sk_listen) { close(sk_listen); }


// onerror: -1
int tcp_server_accept_open(int sk_listen) {

	struct sockaddr_in addr;
	socklen_t len = sizeof addr;

	int client = accept(sk_listen, (struct sockaddr *)&addr, &len);
	if (client < 0) {
		LOG(stderr, "Unable to accept");
		return -1;
	}

	return client;
}

void tcp_server_accept_close(int sk_client) { close(sk_client); }
