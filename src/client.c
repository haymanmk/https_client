#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#define SERVER_NAME "api.restful-api.dev"
#define SERVER_PORT "443"
#define SSL_READ_TIMEOUT_MS 1000

// mbedtls context structures
mbedtls_net_context server_fd;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
const char *cafile = "src/gts-root-r4.pem"; // CA certificate file

static void myDebug( void *ctx, int level,
                      const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

void printResolvedAddress(struct addrinfo *res) {
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

}

// initialize mbedtls
int initMbedTLS() {
    int ret = 0;

    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    // random data generator
    // This string is a small protection against a lack of startup entropy
    // and ensures each application has at least a different starting point.
    char* pers = "mbedtls_ssl_client";
    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                           (const unsigned char *) pers,
                           strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret );
        goto exit;
    }

    // server authentication
    // parse the CA certificate
    mbedtls_x509_crt_init( &cacert );
    if( ( ret = mbedtls_x509_crt_parse_file( &cacert, cafile ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_x509_crt_parse returned -0x%x\n", -ret );
        goto exit;
    }
    printf("CA certificate parsed successfully\n");

    // set up the SSL configuration
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret );
        goto exit;
    }
    printf("mbedtls SSL config defaults set successfully\n");

    // set up SSL config
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_REQUIRED );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg( &conf, myDebug, stdout );
    // mbedtls_ssl_conf_read_timeout( &conf, SSL_READ_TIMEOUT_MS );
    
    // ssl setup
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned -0x%x\n", -ret );
        goto exit;
    }
    printf("mbedtls SSL setup successfully\n");
    // set the hostname
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_set_hostname returned -0x%x\n", -ret );
        goto exit;
    }
    printf("mbedtls SSL hostname set successfully\n");

    // set input and output functions
    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

exit:
    return ret;
}

int main(void) {
    int ret = 0; // return value

    // use dns to resolve the target server
    struct addrinfo hints, *res;

    // Initialize the hints structure
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    ret = getaddrinfo(SERVER_NAME, SERVER_PORT, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        ret = -1;
        goto end;
    }

    // Print the resolved address
    printResolvedAddress(res);

    // create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        ret = -1;
        goto end;
    }
    printf("Socket created successfully\n");

    // initialize mbedtls
    initMbedTLS();

    // connect to the server
    if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                                     SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto end;
    }
    printf("Connected to server %s\n", SERVER_NAME);

    // write to the server with GET request
    const char * req =
        "GET /objects HTTP/1.1\r\n"
        "Host: api.restful-api.dev\r\n"
        "Connection: close\r\n"
        "\r\n";

    // send the request
    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)req, strlen(req))) <= 0) {
        printf(" failed\n  ! mbedtls_ssl_write returned -0x%x\n", -ret);
        goto end;
    }
    printf("GET request sent successfully\n");

    // Read the server's response
    unsigned char buf[4096];
    do {
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            break;
        }

        printf("Server response:\n%s", buf);
    } while (1);

    if (ret < 0) {
        printf(" failed\n  ! mbedtls_ssl_read returned -0x%x\n", -ret);
    } else {
        printf("Connection closed by server\n");
    }

    // connect to the server
    // if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
    //     perror("Failed to connect to server");
    //     ret = -1;
    //     goto end;
    // }
    // printf("Connected to server %s\n", SERVER_NAME);

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