/*****************************************************************************
 *
 *     This file is part of Purdue CS 536.
 *
 *     Purdue CS 536 is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     Purdue CS 536 is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with Purdue CS 536. If not, see <https://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

/*
 * server.c
 * Name: Fenil Gala
 * PUID: 0033439368
 * Colab: Aniket Mohanty
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

/* TODO: server()
 * Open socket and wait for client to connect
 * Print received message to stdout
 * Return 0 on success, non-zero on failure
 */
int server(char *server_port)
{
	struct addrinfo hints, *info;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	struct sockaddr clientaddr;
	socklen_t sin_size;
	int yes = 1;
	char buffer[RECV_BUFFER_SIZE];
	int sockfd, newfd, bytes_rec;
  
	if (getaddrinfo(NULL, server_port, &hints, &info) != 0) {
		perror("getaddrinfo\n");
		freeaddrinfo(info);
		return 1;
	}

	if ((sockfd = socket(info->ai_family, info->ai_socktype, info->ai_protocol)) == -1) {
		perror("socket\n");
		freeaddrinfo(info);
		return 1;
	}
	
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt\n");
		freeaddrinfo(info);
		return 1;
	}

	if (bind(sockfd, info->ai_addr, info->ai_addrlen) == -1) {
		perror("bind\n");
		close(sockfd);
		freeaddrinfo(info);
		return 1;
	}

	if (listen(sockfd, QUEUE_LENGTH) == -1) {
		perror("listen");
		freeaddrinfo(info);
		close(sockfd);
		return 1;
	}
	
	while (1) {
		sin_size = sizeof clientaddr;
		newfd = accept(sockfd, &clientaddr, &sin_size);
		if (newfd == -1) {
			perror("accept\n");
			continue;
		}

		while ((bytes_rec = recv(newfd, buffer, RECV_BUFFER_SIZE, 0)) > 0) {
			if (fwrite(buffer, 1, bytes_rec, stdout) != (size_t)bytes_rec) {
				perror("fwrite\n");
				return 3;
			}
			fflush(stdout);
		}

		if (bytes_rec == -1) {
			perror("recv");
			continue;
		}

		close(newfd);
	}

	close(sockfd);
	freeaddrinfo(info);
	return 0;
}


/*
 * main():
 * Parse command-line arguments and call server function
 */
int main(int argc, char **argv)
{
	char *server_port;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: ./server-c (server port)\n");
		exit(EXIT_FAILURE);
	}

	server_port = argv[1];
	return server(server_port);
}
