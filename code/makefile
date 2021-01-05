all:
	gcc -Wall -o test testec.c util.c ecioprf.c -lcrypto -lssl

net:	net.cpp
	g++ -Iemp-tool/ -Wall -o net net.cpp
old:
	gcc -Wall -o test test.c util.c ioprf.c -lcrypto -lssl
mac:
	gcc -Wall -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lssl -lcrypto -o test testec.c util.c ecioprf.c 
