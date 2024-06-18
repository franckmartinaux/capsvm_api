#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

int main(int argc, char* argv[]){
    //If the number of arguments does not match the expected number
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <newgroupname>\n", argv[0]);
        return 1;
    }
    const char* username = argv[1];
    const char* newgroupname = argv[2];
    sqlite3* db;
    char* err_msg = 0;
    int rc = sqlite3_open("../sql/capsExecutionUser.sqlite", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    //Checking if the user exists in the database
    const char* sql_check = "SELECT COUNT(*) FROM users WHERE username = ?";
    sqlite3_stmt* stmt_check;

    rc = sqlite3_prepare_v2(db, sql_check, -1, &stmt_check, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare check statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    //Check request
    sqlite3_bind_text(stmt_check, 1, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt_check);
    //If user does not exist
    if (rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt_check, 0);
        if (count == 0) {
            fprintf(stderr, "User '%s' does not exist.\n", username);
            sqlite3_finalize(stmt_check);
            sqlite3_close(db);
            return 1;
        }
    } else {
        fprintf(stderr, "Failed to execute check statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt_check);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_finalize(stmt_check);
    //Request to update the groupname of the user
    const char* sql_update = "UPDATE users SET groupname = ? WHERE username = ?";
    sqlite3_stmt* stmt_update;
    rc = sqlite3_prepare_v2(db, sql_update, -1, &stmt_update, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(stmt_update, 1, newgroupname, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt_update, 2, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt_update);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute update statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt_update);
        sqlite3_close(db);
        return 1;
    }
    printf("User '%s' updated successfully.\n", username);

    sqlite3_finalize(stmt_update);
    sqlite3_close(db);
    //Program executed successfully
    return 0;
}