CC=gcc
CFLAGS=-Wall -O6 -fopenmp
DEPS = psi-lib.h net.h

.DEFAULT_GOAL := all

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $< 

psi-server: psi-lib.o psi-server.o net.o symmetric-crypto.o 
	$(CC) -o psi-server psi-lib.o psi-server.o net.o symmetric-crypto.o -fopenmp -lcrypto

psi-client: psi-lib.o psi-client.o net.o symmetric-crypto.o
	$(CC) -o psi-client psi-lib.o psi-client.o net.o symmetric-crypto.o -fopenmp -lcrypto

psi-aux: psi-aux.tex
	rubber -df psi-aux

.PHONY: clean

clean:
	rm -f *.o *~ core psi-server psi-client

all:	psi-server psi-client psi-aux
