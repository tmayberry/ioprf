all:
	gcc -Wfatal-errors -g -o test testec.c util.c ecioprf.c -lcrypto -lssl
mac:
	gcc -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lssl -lcrypto -o test testec.c util.c ecioprf.c 
