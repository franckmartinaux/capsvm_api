##
##  Makefile -- Build procedure for sample capsvm_api Apache module
##  Autogenerated via ``apxs -n capsvm_api -g''.
##

builddir=.
top_srcdir=/etc/httpd
top_builddir=/usr/lib64/httpd
include /usr/lib64/httpd/build/special.mk

APACHECTL=apachectl

.PHONY: all libcapsvm capsvm_api clean restart

all: libcapsvm capsvm_api restart

libcapsvm:
	gcc -c -fPIC -Wincompatible-pointer-types -Wno-discarded-qualifiers -o libcapsvm.o libcapsvm.c
	ar rcs libcapsvm.a libcapsvm.o

capsvm_api: mod_capsvm_api.so

mod_capsvm_api.so: mod_capsvm_api.c libcapsvm.a
	apxs -c -i -Wc,-g -I /usr/include -I /home/julien/capsvm_api -L /usr/lib64 -L /home/julien/capsvm_api -l sqlite3 -l capsvm -l config mod_capsvm_api.c
	cp .libs/mod_capsvm_api.so /etc/httpd/modules/

restart:
	sudo systemctl restart httpd

clean:
	rm -rf *.o .libs *.la *.lo *.slo
