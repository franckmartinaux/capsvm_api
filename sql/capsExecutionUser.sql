CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pw TEXT NOT NULL,
    groupname TEXT NOT NULL
);

DELETE FROM users;
DELETE FROM sqlite_sequence;

INSERT INTO users (username, pw, groupname) VALUES ('user1', 'password1', 'admin');