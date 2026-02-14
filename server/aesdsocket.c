/* Written in reference to https://beej.us/guide/bgnet/html/ */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>

#define PORT "9000"
#define BACKLOG 10

static void print_addrinfo(struct addrinfo *p) {
    char ipstr[INET6_ADDRSTRLEN];
    void *addr;
    char *ipver;

    if (p->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);
        ipver = "IPv4";
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        addr = &(ipv6->sin6_addr);
        ipver = "IPv6";
    }

    inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
    printf(" %s: %s\n", ipver, ipstr);
}

int main() {

    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo hints, *servinfo;
    int ret = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE; // Autofill IP
    hints.ai_socktype = SOCK_STREAM; // TCP stream
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6

    // Allocate address structures that a socket can be binded to
    ret = getaddrinfo(NULL, PORT, &hints, &servinfo);
    if (ret != 0) {
        perror("getaddrinfo");
        return -1;
    }

    // Attempt to bind each possible address until one works
    struct addrinfo *p; 
    int sockfd = -1;
    for (p = servinfo; p != NULL; p = p->ai_next) {

        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue;
        }

        int yes = 1; // Allow port reuse
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        printf("Attempting bind to");
        print_addrinfo(p);
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("bind");
            close(sockfd);
            continue;
        }

        printf("Successful bind\n");
        freeaddrinfo(servinfo);
        break;
    }

    if (sockfd == -1) {
        fprintf(stderr, "Failed to bind to any address\n");
        return -1;
    }

    ret = listen(sockfd, BACKLOG);
    if (ret == -1) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    // Receive new socket for pending connection
    addr_size = sizeof(their_addr);
    ret = accept(sockfd, )


    // Logs messasge to syslog "Accepted connection from xxx" where XXXX is the IP address of connected client

    //
}