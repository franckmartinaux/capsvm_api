#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define SERVER_ADDR "192.168.1.34"
#define PORT 443
#define URL "/capsvm_api/"

char *base64encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    char *encoded_data = (char *)malloc(buffer_ptr->length + 1);
    if (encoded_data) {
        memcpy(encoded_data, buffer_ptr->data, buffer_ptr->length);
        encoded_data[buffer_ptr->length] = '\0';
    }
    BUF_MEM_free(buffer_ptr);

    return encoded_data;
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in serv_addr;
    char request[1024] = {0};
    char response[1024] = {0};

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        SSL_CTX_free(ctx);
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL connection error\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    char username[100];
    char password[100];

    printf("Entrez votre nom d'utilisateur : ");
    scanf("%s", username);

    printf("Entrez votre mot de passe : ");
    scanf("%s", password);

    char combined[256];
    snprintf(combined, sizeof(combined), "%s:%s", username, password);

    char *base64_encoded = base64encode((const unsigned char *)combined, strlen(combined));
    if (!base64_encoded) {
        fprintf(stderr, "Base64 encoding error\n");
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    snprintf(request, sizeof(request), "POST %s HTTP/1.1\r\n"
                                    "Host: %s\r\n"
                                    "Content-Length: 0\r\n"
                                    "Authorization: Basic %s\r\n"
                                    "Content-Type: application/x-www-form-urlencoded\r\n"
                                    "\r\n",
                                    URL, SERVER_ADDR, base64_encoded);


    SSL_write(ssl, request, strlen(request));
    printf("Request sent:\n%s\n", request);

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("Response received:\n%s\n", response);
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
    }

    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
