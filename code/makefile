all:	
	g++ -Wall -Wno-unused-variable -Wno-ignored-attributes -Iemp-tool/ -o test testec.cpp util.cpp ecioprf.cpp -lcrypto -lssl 

net:	net.cpp
	g++ -Iemp-tool/ -Wall -o net net.cpp

mac:
	g++-10 -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -Wall -Wno-unused-variable -Wno-ignored-attributes -Iemp-tool/ -o test testec.cpp util.cpp ecioprf.cpp -lcrypto -lssl

clean:
	rm -f *.o test
