/* 
**  mod_capsvm_api.c -- Apache sample capsvm_api module
**  [Autogenerated via ``apxs -n capsvm_api -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i -I /usr/include -L /usr/lib64 -l sqlite3 mod_capsvm_api.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /capsvm_api in as follows:
**
**    #   httpd.conf
**    LoadModule capsvm_api_module modules/mod_capsvm_api.so
**    <Location /capsvm_api>
**    SetHandler capsvm_api
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /capsvm_api and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/capsvm_api 
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**  
**    The sample page from mod_capsvm_api.c
*/
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "sqlite3.h"
#include "mod_auth.h"
#include "http_request.h"
#include <crypt.h>

#define VERSION "2.7"

static char *db_path;
extern char* status_vm();
extern char* vm_retcode(char *uuid);
extern char* get_uuid_short(char *uuid);
extern char* get_vm_short_list();
extern int ejectcd(char *uuid);
extern int status_vm_fo();
extern int check_role();
extern int start_all_vm_fo();
extern int stop_all_vm_fo();
extern int screendump_vm(char *uuid);
extern int forcestop_vm(char *uuid);
extern int stop_vm(char *uuid);
extern int start_vm(char *uuid);
extern int reset_vm(char *uuid);
extern int find_pid(char *uuid);
extern int read_all_vm_config();
extern int read_common_config();
extern int get_vm_index(char *uuid);
extern int orderstart();
extern int autostart();
extern int create_all_taps();

static int open_sqlite_db(sqlite3 **db) {
    int rc = sqlite3_open_v2(db_path, db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
        const char *err_msg = sqlite3_errmsg(*db);
        const char *err_str = sqlite3_errstr(rc);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Can't open database: %s (%s)", err_msg, err_str);
        sqlite3_close(*db);
        *db = NULL;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return OK;
}

static int close_sqlite_db(sqlite3 *db) {
    if (db) {
        sqlite3_close(db);
    }
    return OK;
}

static authn_status capsvm_check_password(request_rec *r, const char *user, const char *password) {
    sqlite3 *db;
    
    if (open_sqlite_db(&db) != OK) {
        return AUTH_GENERAL_ERROR;
    }

    const char *sql = "SELECT pw, groupname FROM users WHERE username = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        const char *err_msg = sqlite3_errmsg(db);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to prepare statement: %s", err_msg);
        close_sqlite_db(db);
        return AUTH_GENERAL_ERROR;
    }

    if (sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind text");
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return AUTH_GENERAL_ERROR;
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No such user");
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return AUTH_USER_NOT_FOUND;
    }

    const unsigned char *db_groupname = sqlite3_column_text(stmt, 1);
    const unsigned char *db_hashed_password = sqlite3_column_text(stmt, 0);

    char *salt = strdup((const char *)db_hashed_password);
    char *hashed_password = crypt(password, salt);
    free(salt);

    if (hashed_password == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Error hashing password");
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return AUTH_GENERAL_ERROR;
    }

    if (strcmp((const char *)db_hashed_password, hashed_password) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Incorrect password");
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return AUTH_DENIED;
    }

    apr_table_set(r->notes, "user_groupname", (const char *)db_groupname);

    sqlite3_finalize(stmt);
    close_sqlite_db(db);

    create_all_taps();
    read_common_config();
    read_all_vm_config();
    orderstart();
    autostart();
    return AUTH_GRANTED;
}

static int getgroup_handler(request_rec *r) {
    const char *groupname = apr_table_get(r->notes, "user_groupname");
    if (groupname == NULL) {
        groupname = "unknown";
    }

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "%s", groupname);

    return OK;
}

static int adduser_handler(request_rec *r, const char* username, const char* password, const char* groupname) {
    sqlite3 *db;
    if (open_sqlite_db(&db) != OK) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (username == NULL || password == NULL || groupname == NULL) {
        close_sqlite_db(db);
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "Missing username, password or groupname");
        return OK;
    }

    const char *check_sql = "SELECT username FROM users WHERE username = ?";
    sqlite3_stmt *check_stmt;

    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, 0) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to prepare check statement: %s", sqlite3_errmsg(db));
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_bind_text(check_stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind text for check statement: %s", sqlite3_errmsg(db));
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_step(check_stmt) == SQLITE_ROW) {
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "User %s already exists in the database", username);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return OK;
    }

    const char *sql = "INSERT INTO users (username, pw, groupname) VALUES (?, ?, ?)";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to prepare statement: %s", sqlite3_errmsg(db));
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, groupname, -1, SQLITE_STATIC) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind text: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to execute statement: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "User %s added in the database", username);

    sqlite3_finalize(stmt);
    close_sqlite_db(db);
    return OK;
}

static int modifyuser_handler(request_rec *r, const char* username, const char* groupname) {
    sqlite3 *db;
    if (open_sqlite_db(&db) != OK) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (username == NULL || groupname == NULL) {
        close_sqlite_db(db);
        return HTTP_BAD_REQUEST;
    }

    const char *check_sql = "SELECT groupname FROM users WHERE username = ?";
    sqlite3_stmt *check_stmt;

    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, 0) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to prepare check statement: %s", sqlite3_errmsg(db));
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_bind_text(check_stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind text for check statement: %s", sqlite3_errmsg(db));
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_step(check_stmt) != SQLITE_ROW) {
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "User %s does not exist in the database", username);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return OK;
    }

    const unsigned char *db_groupname = sqlite3_column_text(check_stmt, 0);
    if (db_groupname == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to get groupname for user: %s", username);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (strcmp((const char *)db_groupname, groupname) == 0) {
        syslog(LOG_INFO, "modifyuser (%s) user already in group %s", username, groupname);
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "User %s is already in the %s groupname", username, groupname);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return OK;
    } else if (strcmp((const char *)db_groupname, "admin") == 0) {
        syslog(LOG_INFO, "modifyuser (%s) user in admin groupname, cannot modify", username);
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "User %s is in the admin groupname, cannot modify", username);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return OK;
    }

    sqlite3_finalize(check_stmt);

    const char *sql = "UPDATE users SET groupname = ? WHERE username = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to prepare statement: %s", sqlite3_errmsg(db));
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_bind_text(stmt, 1, groupname, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind text: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to execute statement: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "User %s is now in the %s groupname", username, groupname);

    sqlite3_finalize(stmt);
    close_sqlite_db(db);
    return OK;
}


static int deleteuser_handler(request_rec *r, const char* username) {
    sqlite3 *db;
    if (open_sqlite_db(&db) != OK) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (username == NULL) {
        close_sqlite_db(db);
        return HTTP_BAD_REQUEST;
    }

    const char *check_sql = "SELECT groupname FROM users WHERE username = ?";
    sqlite3_stmt *check_stmt;

    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, 0) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to prepare check statement: %s", sqlite3_errmsg(db));
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_bind_text(check_stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind text for check statement: %s", sqlite3_errmsg(db));
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_step(check_stmt) != SQLITE_ROW) {
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "User %s does not exist in the database", username);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return OK;
    }

    const unsigned char *db_groupname = sqlite3_column_text(check_stmt, 0);
    if (db_groupname == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to get groupname for user: %s", username);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (strcmp((const char *)db_groupname, "admin") == 0) {
        syslog(LOG_INFO, "deleteuser (%s) user in admin groupname, cannot delete", username);
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "User %s is in the admin groupname, cannot delete", username);
        sqlite3_finalize(check_stmt);
        close_sqlite_db(db);
        return OK;
    }

    sqlite3_finalize(check_stmt);

    const char *sql = "DELETE FROM users WHERE username = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to prepare statement: %s", sqlite3_errmsg(db));
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind text: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to execute statement: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_sqlite_db(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "User %s has been removed from the database", username);

    sqlite3_finalize(stmt);
    close_sqlite_db(db);
    return OK;
}

static int parse_post_params(request_rec *r, char **short_name, char **function_name, char **username, char **password, char **groupname) {
    apr_array_header_t *pairs;

    if (ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to parse form data");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    for (int i = 0; i < pairs->nelts; i++) {
        ap_form_pair_t *pair = &((ap_form_pair_t *)pairs->elts)[i];
        char *buffer = NULL;
        apr_off_t length;

        apr_brigade_length(pair->value, 1, &length);

        buffer = apr_palloc(r->pool, length + 1);
        if (buffer == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to allocate memory");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        apr_size_t size = (apr_size_t)length;
        if (apr_brigade_flatten(pair->value, buffer, &size) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to flatten brigade");
            continue;
        }
        buffer[size] = '\0';

        if (strcmp(pair->name, "short_name") == 0) {
            *short_name = apr_pstrdup(r->pool, buffer);
        }

        if (strcmp(pair->name, "function") == 0) {
            *function_name = apr_pstrdup(r->pool, buffer);
            if (*function_name == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to duplicate function_name string");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (strcmp(pair->name, "username") == 0) {
            *username = apr_pstrdup(r->pool, buffer);
        }

        if (strcmp(pair->name, "password") == 0) {
            *password = apr_pstrdup(r->pool, buffer);
        }

        if (strcmp(pair->name, "groupname") == 0) {
            *groupname = apr_pstrdup(r->pool, buffer);
        }
    }

    if (*function_name == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "function_name parameter not found");
        return HTTP_BAD_REQUEST;
    }

    return OK;
}


static int start_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (get_vm_index(vm_uuid) == -1) {
        ap_rprintf(r, "start_vm (%s) VM does not exist\n", short_name);
    } else if (find_pid(vm_uuid) > 0) {
        ap_rprintf(r, "start_vm (%s) VM is already running, abort command\n", vm_uuid);
    } else {
        syslog(LOG_INFO, "start_vm (%s) VM started",short_name);
        start_vm(vm_uuid);
        ap_rprintf(r, "VM started");
    }

    return OK;
}

static int stop_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (get_vm_index(vm_uuid) == -1){
        ap_rprintf(r, "stop_vm (%s) VM does not exist\n", short_name);
    } else if(find_pid(vm_uuid) == -1) {
        ap_rprintf(r, "stop_vm (%s) VM already stopped, abort command\n", short_name);
    } else {
        stop_vm(vm_uuid);
        ap_rprintf(r, "VM %s stopped", short_name);
    }

    return OK;
}

static int forcestop_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (get_vm_index(vm_uuid) == -1){
        ap_rprintf(r, "forcestop_vm (%s) VM does not exist\n", short_name);
    } else if (find_pid(vm_uuid) == -1){
        ap_rprintf(r, "forcestop_vm (%s) VM already stopped, abort command\n", short_name);
    } else {
        forcestop_vm(vm_uuid);
        ap_rprintf(r, "VM %s stopped", short_name);
    }

    return OK;
}

static int reset_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");

    if (get_vm_index(vm_uuid) == -1){
        ap_rprintf(r, "reset_vm (%s) VM does not exists, abort command\n", short_name);
    } else {
        reset_vm(vm_uuid);
        ap_rprintf(r, "VM %s reset", short_name);
    }

    return OK;
}

static int status_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (get_vm_index(vm_uuid) == -1){
        ap_rprintf(r, "VM %s does not exist", short_name);
    } else if (find_pid(vm_uuid) >0) {
        ap_rprintf(r, "VM %s is running", short_name);
    } else {
        ap_rprintf(r, "VM %s is not running", short_name);
	}

    return OK;
}

static int statusall_vm_handler(request_rec *r) {

    char *status = status_vm();
    
    if (status == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "%s", status);
    return OK;

}

static int gencode_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (vm_retcode(vm_uuid) != NULL){
        ap_rprintf(r, "VM retcode : %s", vm_retcode(vm_uuid));
    } else {
        ap_rprintf(r, "VM %s does not exist\n", short_name);
    }

    return OK;
}

static int get_uuid_short_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (get_vm_index(vm_uuid) == -1){
        ap_rprintf(r, "The VM does not exists\n");
    } else {
        ap_rprintf(r, "%s", get_uuid_short(short_name));
    }

    return OK;
}

static int version_handler(request_rec *r) {
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "capsvm_api version %s\n", VERSION);
    return OK;
}

static int screendump_vm_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (screendump_vm(vm_uuid) == -1){
        ap_rprintf(r, "The VM does not exists\n");
    } else {
        ap_rprintf(r, "VM %s screendump\n", short_name);
    }

    return OK;
}

static int start_all_vm_fo_handler(request_rec *r) {
    ap_set_content_type(r, "text/plain");
    start_all_vm_fo();
    ap_rprintf(r, "All FO VM started\n");
    return OK;
}

static int stop_all_vm_fo_handler(request_rec *r) {

    ap_set_content_type(r, "text/plain");
    stop_all_vm_fo();
    ap_rprintf(r, "All FO VM stopped\n");

    return OK;
}

static int check_role_handler(request_rec *r) {

    ap_set_content_type(r, "text/plain");
    if(check_role() == -1 ) {
        ap_rprintf(r, "Check_role() role read failed\n");
    } else {
        ap_rprintf(r, "Check_role() role read is %d\n", check_role());
    }

    return OK;
}

static int status_vm_fo_handler(request_rec *r) {

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "%d VM running in failover mode\n", status_vm_fo());

    return OK;
}

static int get_vm_short_list_handler(request_rec *r) {

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "%s", get_vm_short_list());

    return OK;
}

static int ejectcd_handler(request_rec *r, char* vm_uuid, char* short_name) {

    ap_set_content_type(r, "text/plain");
    if (ejectcd(vm_uuid) == -1){
        ap_rprintf(r, "The VM does not exists\n");
    } else {
        ap_rprintf(r, "ejectcd(%s) sending eject command to VM console\n", short_name);
    }

    return OK;
}

static int capsvm_handler(request_rec *r) {
    if (strcmp(r->handler, "capsvm_api") != 0) {
        return DECLINED;
    }

    if (r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    char *short_name = NULL;
    char *function_name = NULL;
    char *username = NULL;
    char *password = NULL;
    char *groupname = NULL;
    if (parse_post_params(r, &short_name, &function_name, &username, &password, &groupname) != OK) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (function_name == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "function_name is required");
        return HTTP_BAD_REQUEST;
    }

    char vm_uuid[64];
    char *uuid = NULL;
    if (short_name != NULL) {
        uuid = get_uuid_short(short_name);
        memset(vm_uuid, 0, sizeof(vm_uuid));
        snprintf(vm_uuid, sizeof(vm_uuid), "%s", uuid);
    }

    if (strcmp(function_name, "getgroup") == 0) {
        return getgroup_handler(r);
    } else if (strcmp(function_name, "adduser") == 0 && strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0) {
        return adduser_handler(r, username, password, groupname);
    } else if (strcmp(function_name, "modifyuser") == 0 && strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0){
        return modifyuser_handler(r, username, groupname);
    } else if (strcmp(function_name, "removeuser") == 0 && strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0){
        return deleteuser_handler(r, username);
    } else if (strcmp(function_name, "startvm") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)) {
        return start_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "stopvm") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)){
        return stop_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "forcestopvm") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)){
        return forcestop_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "resetvm") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)){
        return reset_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "statusvm") == 0) {
        return status_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "statusallvm") == 0) {
        return statusall_vm_handler(r);
    } else if (strcmp(function_name, "gencodevm") == 0) {
        return gencode_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "getuuidshortvm") == 0) {
        return get_uuid_short_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "version") == 0) {
        return version_handler(r);
    } else if (strcmp(function_name, "screendumpvm") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)){
        return screendump_vm_handler(r, vm_uuid, short_name);
    } else if (strcmp(function_name, "startallvmfo") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)) {
        return start_all_vm_fo_handler(r);
    } else if (strcmp(function_name, "stopallvmfo") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)) {
        return stop_all_vm_fo_handler(r);
    } else if (strcmp(function_name, "checkrole") == 0) {
        return check_role_handler(r);
    } else if (strcmp(function_name, "statusvmfo") == 0) {
        return status_vm_fo_handler(r);
    } else if (strcmp(function_name, "getvmshortlist") == 0) {
        return get_vm_short_list_handler(r);
    } else if (strcmp(function_name, "ejectcd") == 0 && (strcmp(apr_table_get(r->notes, "user_groupname"), "admin") == 0 || strcmp(apr_table_get(r->notes, "user_groupname"), "moderator") == 0)) {
        return ejectcd_handler(r, vm_uuid, short_name);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unknown function_name: %s", function_name);
        return HTTP_NOT_FOUND;
    }

    return OK;
}


static const authn_provider capsvm_auth_provider = {
    &capsvm_check_password,
    NULL
};

static const char *set_auth_basic_provider(cmd_parms *cmd, void *config, const char *arg) {
    if (strcasecmp(arg, "capsvm_api_module") != 0) {
        return "Invalid provider name";
    }
    return NULL;
}

static const char *set_db_path(cmd_parms *cmd, void *config, const char *arg) {
    db_path = apr_pstrdup(cmd->pool, arg);
    if (db_path == NULL) {
        return "Failed to copy db path";
    }
    return NULL;
}

static const command_rec capsvm_api_cmds[] = {
    AP_INIT_TAKE1("AuthBasicProvider", set_auth_basic_provider, NULL, OR_AUTHCFG, "Set the authentication provider for Basic authentication"),
    AP_INIT_TAKE1("SetDbPAth", set_db_path, NULL, OR_AUTHCFG, "Set the path to the sqlite database"),
    {NULL}
};

static void capsvm_api_register_hooks(apr_pool_t *p) {
    ap_hook_handler(capsvm_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "capsvm_api_module", AUTHN_PROVIDER_VERSION, &capsvm_auth_provider, AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA capsvm_api_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    capsvm_api_cmds,       /* table of config file commands       */
    capsvm_api_register_hooks  /* register hooks                      */
};