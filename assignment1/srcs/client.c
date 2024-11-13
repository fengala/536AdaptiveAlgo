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
 * client.c
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

#define SEND_BUFFER_SIZE 2048

/* TODO: client()
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
 */
int client(char *server_ip, char *server_port)
{
    struct addrinfo hints, *info;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int sockfd;

    char buffer[SEND_BUFFER_SIZE];
    ssize_t read, sent, total;
    
    if (getaddrinfo(server_ip, server_port, &hints, &info) != 0) {
        perror("getaddrinfo\n");
        freeaddrinfo(info);
        return 1;
    }

    if ((sockfd = socket(info->ai_family, info->ai_socktype, info->ai_protocol)) == -1) {
        perror("socket\n");
        freeaddrinfo(info);
        return 1;
    }

    if (connect(sockfd, info->ai_addr, info->ai_addrlen) == -1) {
        perror("connect\n");
        freeaddrinfo(info);
        close(sockfd);
        return 1;
    }

    while ((read = fread(buffer, 1, SEND_BUFFER_SIZE, stdin)) > 0) {
        total = 0;
        while (total < read) {
            sent = send(sockfd, buffer + total, read - total, 0);
            if (sent == -1) {
                perror("sending\n");
                freeaddrinfo(info);
                close(sockfd);
                return 1;
            }
            total += sent;
        }
    }

    if (read == -1) {
        perror("reading\n");
        freeaddrinfo(info);
        close(sockfd);
        return 1;
    }

    close(sockfd);
    freeaddrinfo(info);
    return 0;
}


/*
 * main()
 * Parse command-line arguments and call client function
 */
int main(int argc, char **argv)
{
    char *server_ip;
    char *server_port;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: ./client-c (server IP) (server port) < (message)\n");
        exit(EXIT_FAILURE);
    }

    server_ip = argv[1];
    server_port = argv[2];
    return client(server_ip, server_port);
}
