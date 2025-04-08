#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define TARGET_SERVER "api.restful-api.dev"
#define TARGET_PORT "443"

int main(void) {
    int ret = 0; // return value

    // use dns to resolve the target server
    struct addrinfo hints, *res;

    // Initialize the hints structure
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    ret = getaddrinfo(TARGET_SERVER, TARGET_PORT, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        ret = -1;
        goto end;
    }

    // Print the resolved address
    char ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(res->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    printf("Resolved IP address: %s\n", ipstr);
    // Print the port number
    printf("Port number: %d\n", ntohs(ipv4->sin_port));
    // Print the canonical name
    if (res->ai_canonname) {
        printf("Canonical name: %s\n", res->ai_canonname);
    } else {
        printf("No canonical name available\n");
    }
    // Print the socket type
    switch (res->ai_socktype) {
        case SOCK_STREAM:
            printf("Socket type: TCP\n");
            break;
        case SOCK_DGRAM:
            printf("Socket type: UDP\n");
            break;
        default:
            printf("Socket type: Unknown\n");
            break;
    }
    // Print the address family
    switch (res->ai_family) {
        case AF_INET:
            printf("Address family: IPv4\n");
            break;
        case AF_INET6:
            printf("Address family: IPv6\n");
            break;
        default:
            printf("Address family: Unknown\n");
            break;
    }
    // create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        ret = -1;
        goto end;
    }

    // connect to the server
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("Failed to connect to server");
        ret = -1;
        goto end;
    }
    printf("Connected to server %s\n", TARGET_SERVER);

end:
    // release resources
    if (res) {
        freeaddrinfo(res); // Free the linked list
    }
    if (sockfd >= 0) {
        close(sockfd); // Close the socket
    }
    // return the result
    return ret;
}