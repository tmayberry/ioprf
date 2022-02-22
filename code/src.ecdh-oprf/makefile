CC=gcc-11
CFLAGS=-Wall -O6 -fopenmp -I/usr/local/opt/openssl/include 
LDFLAGS=-L/usr/local/opt/openssl/lib
DEPS = psi-lib.h net.h

.DEFAULT_GOAL := all

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $< 

psi-server: psi-lib.o psi-server.o net.o symmetric-crypto.o 
	$(CC) $(LDFLAGS) -o psi-server psi-lib.o psi-server.o net.o symmetric-crypto.o -fopenmp -lcrypto

psi-client: psi-lib.o psi-client.o net.o symmetric-crypto.o
	$(CC) $(LDFLAGS) -o psi-client psi-lib.o psi-client.o net.o symmetric-crypto.o -fopenmp -lcrypto

.PHONY: clean

clean:
	rm -f *.o *~ core psi-server psi-client

all:	psi-server psi-client
