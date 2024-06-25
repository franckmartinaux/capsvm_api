#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define SERVER_ADDR "192.168.1.34"
#define PORT 443
#define URL "/capsvm_api/"

SSL* connect_ssl(SSL_CTX *ctx, struct sockaddr_in *serv_addr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation error");
        return NULL;
    }

    if (connect(sockfd, (struct sockaddr *)serv_addr, sizeof(*serv_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new failed\n");
        close(sockfd);
        return NULL;
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL connection error\n");
        SSL_free(ssl);
        close(sockfd);
        return NULL;
    }

    return ssl;
}


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

/**
 * @brief Hashes a password using bcrypt.
 * 
 * @param password The password to hash.
 * @return char* The hashed password.
 */
char* hash_password(const char *password) {
    char salt[30] = "$2b$12$";
    const char *salt_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
    for (int i = 7; i < 29; i++) {
        salt[i] = salt_chars[rand() % 64];
    }
    salt[29] = '\0';

    char *hashed_password = crypt(password, salt);
    if (hashed_password == NULL) {
        fprintf(stderr, "Error hashing password\n");
        exit(-1);
    }
    return hashed_password;
}

void admin_menu() {
    printf("Je suis administrateur let's go !\n");
}

char *get_groupname(SSL_CTX *ctx, SSL *ssl, char *combined) {
    char request[1024] = {0};
    char response[1024] = {0};

    snprintf(request, sizeof(request), "POST %sgetgroup/ HTTP/1.1\r\n"
                                    "Host: %s\r\n"
                                    "Content-Length: 0\r\n"
                                    "Authorization: Basic %s\r\n"
                                    "Content-Type: application/x-www-form-urlencoded\r\n"
                                    "\r\n",
                                    URL, SERVER_ADDR, combined);

    SSL_write(ssl, request, strlen(request));
    printf("Request sent:\n%s\n", request);

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    char *pos = NULL;
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("Response received:\n%s\n", response);

        pos = strstr(response, "\r\n\r\n");
        if (pos) {
            pos += 4;
        }
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return pos;
}

int add_user(SSL_CTX *ctx, SSL *ssl, char *new_Username, char *new_password, char *new_Groupname, char *combined) {
    char request[1024] = {0};
    char response[1024] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "username=%s&password=%s&groupname=%s", new_Username, new_password, new_Groupname);

    snprintf(request, sizeof(request), "POST %smanagement/adduser/ HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, SERVER_ADDR, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));
    printf("Request sent:\n%s\n", request);

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("Response received:\n%s\n", response);
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

int modify_user(SSL_CTX *ctx, SSL *ssl, char *username, char *new_groupname, char *combined) {
    char request[1024] = {0};
    char response[1024] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "username=%s&groupname=%s", username, new_groupname);

    snprintf(request, sizeof(request), "POST %smanagement/modifyuser/ HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, SERVER_ADDR, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));
    printf("Request sent:\n%s\n", request);

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("Response received:\n%s\n", response);
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

int remove_user(SSL_CTX *ctx, SSL *ssl, char *username, char *combined) {
    char request[1024] = {0};
    char response[1024] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "username=%s", username);

    snprintf(request, sizeof(request), "POST %smanagement/removeuser/ HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, SERVER_ADDR, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));
    printf("Request sent:\n%s\n", request);

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("Response received:\n%s\n", response);
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in serv_addr;
    char user_groupname[100] = {0};

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }

    ssl = connect_ssl(ctx, &serv_addr);

    char username[100];
    char password[100];

    printf("Enter your username: ");
    scanf("%s", username);

    printf("Enter your password: ");
    scanf("%s", password);

    char combined[256];
    snprintf(combined, sizeof(combined), "%s:%s", username, password);
    char *base64_encoded = base64encode((const unsigned char *)combined, strlen(combined));
    if (!base64_encoded) {
        fprintf(stderr, "Base64 encoding error\n");
        return -1;
    }

    char *groupname = get_groupname(ctx, ssl, base64_encoded);
    if (groupname) {
        strncpy(user_groupname, groupname, sizeof(user_groupname) - 1);
        printf("Group name: %s\n", user_groupname);
    } else {
        printf("Failed to fetch groupname\n");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    if (user_groupname != NULL && strcmp(user_groupname, "admin") == 0) {
        admin_menu();
        printf("1 : add user\n");
        printf("2 : modify user\n");
        printf("3 : delete user\n");
        int choice;
        scanf("%d", &choice);
        if (choice == 1) {
            char new_Username[100];
            char new_password[100];
            char new_Groupname[100];

            printf("Enter the username: ");
            scanf("%s", new_Username);
            printf("Enter the password: ");
            scanf("%s", new_password);
            printf("Enter the groupname: ");
            scanf("%s", new_Groupname);

            char *hash_newPassword = hash_password(new_password);

            ssl = connect_ssl(ctx, &serv_addr);

            add_user(ctx, ssl, new_Username, hash_newPassword, new_Groupname, base64_encoded);

            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        else if (choice == 2){
            char new_username[100];
            char new_groupname[100];

            printf("Enter the username: ");
            scanf("%s", new_username);
            printf("Enter the new groupname: ");
            scanf("%s", new_groupname);

            ssl = connect_ssl(ctx, &serv_addr);

            modify_user(ctx, ssl, new_username, new_groupname, base64_encoded);

            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        else if (choice == 3){
            char new_username[100];

            printf("Enter the username: ");
            scanf("%s", new_username);

            ssl = connect_ssl(ctx, &serv_addr);

            remove_user(ctx, ssl, new_username, base64_encoded);

            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    } else {
        printf("You do not have administrative privileges.\n");
    }

    free(base64_encoded);
    SSL_CTX_free(ctx);

    return 0;
}
