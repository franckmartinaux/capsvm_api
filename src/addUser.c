#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <crypt.h>
#include <time.h>
#include <string.h>

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

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <username> <password> <groupname>\n", argv[0]);
        return 1;
    }
    const char* username = argv[1];
    const char* password = argv[2];
    const char* groupname = argv[3];
    sqlite3* db;
    char* err_msg = 0;
    int rc = sqlite3_open("../sql/capsExecutionUser.sqlite", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    srand(time(NULL));
    char* hashed_password = hash_password(password);

    char* sql = "INSERT INTO users (username, pw, groupname) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed_password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, groupname, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    printf("%s inserted with hashed password.\n", username);
    return 0;
}
