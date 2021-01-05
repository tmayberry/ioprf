all:	
	g++ -Wall -Wno-ignored-attributes -Iemp-tool/ -o test testec.cpp util.cpp ecioprf.cpp -lcrypto -lssl 

net:	net.cpp
	g++ -Iemp-tool/ -Wall -o net net.cpp
old:
	gcc -Wall -o test test.c util.c ioprf.c -lcrypto -lssl
mac:
	gcc -Wall -O6 -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lssl -lcrypto -o test testec.c util.c ecioprf.c

clean:
	rm -f *.o test
