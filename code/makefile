all:
	gcc -g -o test *.c -lcrypto -lssl
mac:
	gcc -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lssl -lcrypto -o test *.c 
