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
#include <readline/readline.h>
#include <readline/history.h>
#include <termios.h>
#include <syslog.h>

#define PORT 443
#define URL "/capsvm_api/"
#define VERSION "2.1"
#define LIMIT 256
#define MAXLINE 1024
#define TRUE 1

void splashScreen(char* server_ip);
void getPassword(char *password, size_t size);
SSL *connect_ssl(SSL_CTX *ctx, struct sockaddr_in *serv_addr);
char *base64encode(const unsigned char *input, int length);
char *hash_password(const char *password);
char *get_groupname(SSL_CTX *ctx, SSL *ssl, char *combined, char* server_ip);
char *shellPrompt();
int add_user(SSL_CTX *ctx, SSL *ssl, char *new_Username, char *new_password, char *new_Groupname, char *combined, char* server_ip);
int modify_user(SSL_CTX *ctx, SSL *ssl, char *username, char *new_groupname, char *combined, char* server_ip);
int remove_user(SSL_CTX *ctx, SSL *ssl, char *username, char *combined, char* server_ip);
int send_request(SSL_CTX *ctx, SSL *ssl, char* shortname, char* combined, char* called, char* server_ip);
int commandHandler(char * args[], char *base64_login, SSL_CTX *ctx, SSL *ssl, char *groupname, char** server_ip);

void splashScreen(char* server_ip){
        printf("\n\t================================================================\n");
        printf("\t          CAPSVMAPI - Application Programming Interface\n");
        printf("\t----------------------------------------------------------------\n");
        printf("\t          (c) 2020-2024 Capsule Technologies France SAS.\n");
        printf("\t          (c) 2019 Capsule Technologies (Pty) Ltd.\n");
        printf("\t================================================================\n");
		printf("\tVersion - %s \n",VERSION);
        printf("\tConnected on server %s\n", server_ip);
        printf("\tType help for help, exit to quit\n\n");
}

SSL *connect_ssl(SSL_CTX *ctx, struct sockaddr_in *serv_addr) {
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
char *hash_password(const char *password) {
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

char *get_groupname(SSL_CTX *ctx, SSL *ssl, char *combined, char* server_ip) {
    char request[1024] = {0};
    char response[1024] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "function=getgroup");

    snprintf(request, sizeof(request), "POST %s/ HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, server_ip, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    char *pos = NULL;
    if (bytes > 0) {
        response[bytes] = '\0';

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

int add_user(SSL_CTX *ctx, SSL *ssl, char *new_Username, char *new_password, char *new_Groupname, char *combined, char* server_ip) {
    char request[1024] = {0};
    char response[1024] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "function=adduser&username=%s&password=%s&groupname=%s", new_Username, new_password, new_Groupname);

    snprintf(request, sizeof(request), "POST %s HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, server_ip, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';

        char *body = strstr(response, "\r\n\r\n");
        if (body) {
            body += 4;
            printf("\n%s\n", body);
        }
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

int modify_user(SSL_CTX *ctx, SSL *ssl, char *username, char *new_groupname, char *combined, char* server_ip) {
    char request[1024] = {0};
    char response[1024] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "function=modifyuser&username=%s&groupname=%s", username, new_groupname);

    snprintf(request, sizeof(request), "POST %s HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, server_ip, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';

        char *body = strstr(response, "\r\n\r\n");
        if (body) {
            body += 4;
            printf("\n%s\n", body);
        }
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

int remove_user(SSL_CTX *ctx, SSL *ssl, char *username, char *combined, char* server_ip) {
    char request[1024] = {0};
    char response[1024] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "function=removeuser&username=%s", username);

    snprintf(request, sizeof(request), "POST %s HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, server_ip, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';

        char *body = strstr(response, "\r\n\r\n");
        if (body) {
            body += 4;
            printf("\n%s\n", body);
        }
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}


int send_request(SSL_CTX *ctx, SSL *ssl, char* shortname, char* combined, char* called, char* server_ip){
    char request[1024] = {0};
    char response[4096] = {0};

    char data[1024] = {0};
    snprintf(data, sizeof(data), "function=%s&short_name=%s", called, shortname);

    snprintf(request, sizeof(request), "POST %s/ HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Authorization: Basic %s\r\n"
                                        "Content-Type: application/x-www-form-urlencoded\r\n"
                                        "Content-Length: %d\r\n"
                                        "\r\n"
                                        "%s",
                                        URL, server_ip, combined,
                                        (int)strlen(data), data);

    SSL_write(ssl, request, strlen(request));

    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';

        char *body = strstr(response, "\r\n\r\n");
        if (body) {
            body += 4;
            printf("\n%s\n", body);
        }
    } else {
        fprintf(stderr, "SSL read error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

char *shellPrompt() {
    static char prompt[1024];
    char hostn[1024] = "";
    gethostname(hostn, sizeof(hostn));
    snprintf(prompt, sizeof(prompt), "%s@%s > ", "CAPSVMAPI", hostn);
    return prompt;
}

int commandHandler(char * args[], char *base64_login, SSL_CTX *ctx, SSL *ssl, char *groupname, char** server_ip){
    int j = 0;

    char *args_aux[256];

    while ( args[j] != NULL) {
		if ( (strcmp(args[j],">") == 0) || (strcmp(args[j],"<") == 0) || (strcmp(args[j],"&") == 0)){
			break;
		}
		args_aux[j] = args[j];
		j++;
	}

    if(strcmp(args[0], "reset-vm") == 0 && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "resetvm", *server_ip);
        } else {
            printf("Usage: reset-vm <shortname>\n");
        }
    }

    else if(strcmp(args[0], "show") == 0){
        if(strcmp(args[1], "code") == 0){
            if(args[2] != NULL) {
                send_request(ctx, ssl, args[2], base64_login, "gencodevm", *server_ip);
            } else {
                printf("Usage: show code <shortname>\n");
            }
        }
    }

    else if(strcmp(args[0], "add-user") == 0 && strcmp(groupname, "admin") == 0){
        if(args[1] != NULL && args[2] != NULL && args[3] != NULL && (strcmp(args[3], "admin") == 0 || strcmp(args[3], "moderator") == 0 || strcmp(args[3], "user") == 0)){
            add_user(ctx, ssl, args[1], hash_password(args[2]), args[3], base64_login, *server_ip);
        } else if (args[1] != NULL && args[2] != NULL && args[3] == NULL) {
            printf("Usage: add-user <username> <password> <groupname>\n");
        } else {
            printf("You need to enter a correct groupname : admin / moderator / user\n");
        }
    }

    else if(strcmp(args[0], "modify-user") == 0  && strcmp(groupname, "admin") == 0){
        if(args[1] != NULL && args[2] != NULL) {
            modify_user(ctx, ssl, args[1], args[2], base64_login, *server_ip);
        } else {
            printf("Usage: modify-user <username> <groupname>\n");
        }
    }

    else if(strcmp(args[0], "remove-user") == 0 && strcmp(groupname, "admin") == 0){
        if(args[1] != NULL) {
            remove_user(ctx, ssl, args[1], base64_login, *server_ip);
        } else {
            printf("Usage: remove-user <username>\n");
        }
    }

    else if(strcmp(args[0], "start-vm") == 0  && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "startvm", *server_ip);
        } else {
            printf("Usage: start-vm <shortname>\n");
        }
    }

    else if(strcmp(args[0], "stop-vm") == 0  && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "stopvm", *server_ip);
        } else {
            printf("Usage: stop-vm <shortname>\n");
        }
    }

    else if(strcmp(args[0], "forcestop-vm") == 0  && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "forcestopvm", *server_ip);
        } else {
            printf("Usage: forcestop-vm <shortname>\n");
        }
    }

    else if(strcmp(args[0], "status-vm") == 0) {
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "statusvm", *server_ip);
        } else {
            printf("Usage: status-vm <shortname>\n");
        }
    }

    else if(strcmp(args[0], "status-all-vm") == 0) {
        send_request(ctx, ssl, "all", base64_login, "statusallvm", *server_ip);
    }

    else if(strcmp(args[0], "get-uuid") == 0) {
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "getuuidshortvm", *server_ip);
        } else {
            printf("Usage: get-uuid <shortname>\n");
        }
    }

    else if(strcmp(args[0], "version") == 0) {
        send_request(ctx, ssl, "all", base64_login, "version", *server_ip);
    }

    else if(strcmp(args[0], "screendump-vm") == 0 && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "screendumpvm", *server_ip);
        } else {
            printf("Usage: screendump-vm <shortname>\n");
        }
    }

    else if(strcmp(args[0], "start-all-vm-fo") == 0  && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        send_request(ctx, ssl, "all", base64_login, "startallvmfo", *server_ip);
    }

    else if(strcmp(args[0], "stop-all-vm-fo") == 0  && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        send_request(ctx, ssl, "all", base64_login, "stopallvmfo", *server_ip);
    }

    else if(strcmp(args[0], "check-role") == 0) {
        send_request(ctx, ssl, "", base64_login, "checkrole", *server_ip);
    }

    else if(strcmp(args[0], "status-vm-fo") == 0) {
        send_request(ctx, ssl, "allfo", base64_login, "statusvmfo", *server_ip);
    }

    else if(strcmp(args[0], "get-vm-short-list") == 0) {
        send_request(ctx, ssl, "allfo", base64_login, "getvmshortlist", *server_ip);
    }

    else if(strcmp(args[0], "ejectcd") == 0 && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        if(args[1] != NULL) {
            send_request(ctx, ssl, args[1], base64_login, "ejectcd", *server_ip);
        } else {
            printf("Usage: ejectcd <shortname>\n");
        }
    }

    else if(strcmp(args[0], "vm") == 0 && (strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0)){
        if(strcmp(args[1], "status") == 0) {
            if(args[2] != NULL) {
                send_request(ctx, ssl, args[2], base64_login, "statusvm", *server_ip);
            } else {
                printf("Usage: vm status <shortname>\n");
            }
        }

        if(strcmp(args[1], "start") == 0) {
            if(args[2] != NULL) {
                send_request(ctx, ssl, args[2], base64_login, "startvm", *server_ip);
            } else {
                printf("Usage: vm start <shortname>\n");
            }
        }

        if(strcmp(args[1], "stop") == 0) {
            if(args[2] != NULL) {
                send_request(ctx, ssl, args[2], base64_login, "stopvm", *server_ip);
            } else {
                printf("Usage: vm stop <shortname>\n");
            }
        }

        if(strcmp(args[1], "forcestop") == 0) {
            if(args[2] != NULL) {
                send_request(ctx, ssl, args[2], base64_login, "forcestopvm", *server_ip);
            } else {
                printf("Usage: vm forcestop <shortname>\n");
            }
        }

        if(strcmp(args[1], "reset") == 0) {
            if(args[2] != NULL) {
                send_request(ctx, ssl, args[2], base64_login, "resetvm", *server_ip);
            } else {
                printf("Usage: vm reset <shortname>\n");
            }
        }
    }

    else if((strcmp(args[0], "help") == 0) || (strcmp(args[0], "h") == 0)){ 
        printf("\n\t================================================================\n");
        printf("\t\t          CAPSVMAPI - Help Interface\n");
        printf("\t----------------------------------------------------------------\n\n");
        if(strcmp(groupname, "admin") == 0) {
            printf("User management:\n\n");
            printf("add-user <username> <password> <groupname> - Add a user\n");
            printf("modify-user <username> <groupname> - Modify a user\n");
            printf("remove-user <username> - Remove a user\n\n\n");
        }
        printf("VM management:\n\n");
        printf("Normal mode:\n");
        if(strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0) {
            printf("start-vm <shortname> - Start a VM\n");
            printf("stop-vm <shortname> - Stop a VM\n");
            printf("reset-vm <shortname> - Reset a VM\n");
            printf("forcestop-vm <shortname> - Force stop a VM\n");
        }
        printf("status-vm <shortname> - Get the status of a VM\n");
        printf("status-all-vm - Get the status of all VMs\n");
        printf("get-uuid <shortname> - Get the UUID of a VM\n");
        printf("show code <shortname> - Show the code of a VM\n");
        if(strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0) {
            printf("screendump-vm <shortname> - Get a screendump of a VM\n");
            printf("ejectcd <shortname> - Eject the CD from a VM\n");
        }
        printf("\nFailover mode:\n");
        if(strcmp(groupname, "admin") == 0 || strcmp(groupname, "moderator") == 0) {
            printf("start-all-vm-fo - Start all VMs in the FO group\n");
            printf("stop-all-vm-fo - Stop all VMs in the FO group\n");
        }
        printf("status-vm-fo - Get the status of all VMs in the FO group\n");
        printf("get-vm-short-list - Get a short list of all VMs in the FO group\n\n\n");
        printf("General:\n\n");
        printf("exit - Exit the program\n");
        printf("connect <server_ip> - Connect to a different server\n");
        printf("clear - Clear the screen\n");
        printf("version - Get the version of the server\n");
        printf("check-role - Check the role of the server\n");
    }

    else if(strcmp(args[0], "clear") == 0) {
        system("clear");
    }

    else if(strcmp(args[0], "exit") == 0) {
        exit(0);
    }
    else if(strcmp(args[0], "connect") == 0 && args[1] != NULL) {
        *server_ip = args[1];
        return 1;
    } else {
        printf("\nCommand not found. Use help for help.\n");
    }

    return 0;
}

void getPassword(char *password, size_t size) {
    struct termios oldt, newt;

    printf("Enter your password: ");
    fflush(stdout); 

    tcgetattr(STDIN_FILENO, &oldt); 
    newt = oldt;
    newt.c_lflag &= ~ECHO; 
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); 

    fgets(password, size, stdin); 

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); 

    size_t len = strlen(password);
    if (len > 0 && password[len-1] == '\n') {
        password[len-1] = '\0';
    }
}

int main(int argc, char *argv[], char ** envp) {
    if (argc != 2) {
        printf("Usage: %s <server_ip>\n", argv[0]);
        return -1;
    }
    char line[MAXLINE];
	char * tokens[LIMIT];
	int numTokens;
    char* server_ip = argv[1];

    char *input;
    using_history();

    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in serv_addr;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    while (TRUE) {
        system("clear");

        if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address/ Address not supported");
            close(sockfd);
            SSL_CTX_free(ctx);
            return -1;
        }

        char username[100];
        char password[100];

        char *username_input = readline("Enter your username: ");
        if (username_input) {
            strncpy(username, username_input, sizeof(username));
            username[sizeof(username) - 1] = '\0';
            free(username_input);
        } else {
            fprintf(stderr, "Error reading username\n");
            return -1;
        }

        getPassword(password, sizeof(password));

        char combined[256];
        snprintf(combined, sizeof(combined), "%s:%s", username, password);
        char *base64_login = base64encode((const unsigned char *)combined, strlen(combined));
        if (!base64_login) {
            fprintf(stderr, "Base64 encoding error\n");
            return -1;
        }

        ssl = connect_ssl(ctx, &serv_addr);
        char *groupname = get_groupname(ctx, ssl, base64_login, server_ip);
        char *usergroup = strdup(groupname);

        SSL_shutdown(ssl);
        SSL_free(ssl);

        system("clear");
        splashScreen(server_ip);

        int resCommand = 0;

        while(TRUE && resCommand != 1){
            printf("\n");
            
            input = readline(shellPrompt());
            if (input == NULL) {
                continue;
            }

            if (strlen(input) > 0) {
                add_history(input);
            }

            strncpy(line, input, MAXLINE);
            free(input);
        
            if((tokens[0] = strtok(line," \n\t")) == NULL) continue;
            
            numTokens = 1;
            while((tokens[numTokens] = strtok(NULL, " \n\t")) != NULL) numTokens++;
            
            ssl = connect_ssl(ctx, &serv_addr);

            if(commandHandler(tokens, base64_login, ctx, ssl, usergroup, &server_ip) == 0){
                continue;
            } else {
                resCommand = 1;
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
        }          

        free(usergroup);
        free(base64_login);
    }

    SSL_CTX_free(ctx);

    return 0;
}
