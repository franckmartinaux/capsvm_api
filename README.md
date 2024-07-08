# Capsvm Application Programming Interface

## Authors

    - Gitton Julien
    - Soutric Tanguy

## Project description

This project goal is to secure the VMs management for capsos on Alma Linux

## Running instructions

### Required libraries

#### Prerequisites

- httpd installed on the server side:

    **Install httpd**
    ```sh
    sudo dnf install httpd-devel -y
    ```

- SQLite installed on the server side:

    **Install SQLite**
    ```sh 
    sudo dnf install sqlite -y
    ```

- Readline installed on the client side :

    **Install Readline**
    ```sh
    sudo dnf install readline readline-devel -y
    ```

- OpenSSL installed on the client side :

    **Install OpenSS**
    ```sh
    sudo dnf install openssl openssl-devel -y
    ```

- SQLite dabase in /var/lib/capsvm_api_db with read and write rights for httpd :

    ```sh
    chmod 664 /var/lib/capsvm_api/capsExecutionUser.sqlite
    ```

- Put the mod_capsvm_api.so in module directory

    ```sh
    mv mod_capsvm_api.so /etc/httpd/modules/
    ```

### How to use it

- Once you have all the librairies installed, you need to compile the client

    ```sh
    gcc -c -o client.exe client.c -lcrypt -lcrypto -lssl -lreadline
    ```

- Start the client and enter your username and password to access the API.

The default administrator for the API is authentified with `user1` and `password1`, you may add a new user to the database to gain access and then 
remove the default one.

You can't modify or remove an admin user via the client, you'll have to remove it from the .sqlite file.

There are 3 differents groups : `admin`, that can access everything, `moderator`, that can not access the database related functionalities and `user`, that can
only see the informations of the VMs.