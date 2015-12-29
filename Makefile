rfc5077-checker:rfc5077-checker.c
	gcc -Wall -I/opt/dst/ssl/include/ -L/opt/dst/ssl/lib/ -o rfc5077-checker rfc5077-checker.c  -lssl -lcrypto -ldl -lpthread
