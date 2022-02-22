CC=g++-10
CFLAGS =-O6  -Wall -Wno-unused-variable -Wno-ignored-attributes -Iemp-tool/ 
MACFLAGS=-O6 -I/usr/local/opt/openssl/include -Wall -Wno-unused-command-line-argument -Wno-unused-variable -Wno-ignored-attributes -Iemp-tool/ -L/usr/local/opt/openssl/lib

DEPS=ecioprf.h util.h zkp.h

.DEFAULT_GOAL := all

%.o: %.cpp $(DEPS)
	$(CC) $(MACFLAGS) -c -o $@ $<

all: malicious

sh:	semi-honest.o util.o ecioprf.o $(DEPS)	
	g++ $(CFLAGS) -o semi-honest semi-honest.o util.o ecioprf.o  -lcrypto -lssl 

sh-mac:	semi-honest.o util.o ecioprf.o $(DEPS)
	g++-10 $(MACFLAGS) -o semi-honest semi-honest.o util.o ecioprf.o -lcrypto -lssl

testProofOfPTKnowledge: testProofOfPTKnowledge.o zkp.o util.o $(DEPS)
	g++ $(CFLAGS)-o testProofOfPTKnowledge testProofOfPTKnowledge.o zkp.o util.o  -lcrypto -lssl


testProofOfPTKnowledge-mac: testProofOfPTKnowledge.o zkp.o util.o $(DEPS)
	g++-10  $(MACFLAGS) -o testProofOfPTKnowledge testProofOfPTKnowledge.o zkp.o util.o  -lcrypto -lssl

testProofOfBit: testProofOfBit.o zkp.o util.o ecioprf.o
	g++ $(CFLAGS) -o testProofOfBit testProofOfBit.o zkp.o util.o ecioprf.o -lcrypto -lssl

testProofOfBit-mac: testProofOfBit.o zkp.o util.o ecioprf.o
	g++-10 $(MACFLAGS) -o testProofOfBit testProofOfBit.o zkp.o util.o ecioprf.o -lcrypto -lssl

malicious: malicious.o zkp.o util.o ecioprf.o $(DEPS) 
	g++ $(CFLAGS) -o malicious  zkp.o malicious.o util.o ecioprf.o -lcrypto -lssl


malicious-mac: malicious.o zkp.o util.o ecioprf.o $(DEPS) 
	g++-10 $(MACFLAGS) -o malicious zkp.o malicious.o util.o ecioprf.o -lcrypto -lssl


testProofEnc: testProofEnc.o zkp.o util.o
	g++ $(CFLAGS) -o testProofEnc util.o testProofEnc.o zkp.o -lcrypto -lssl

testProofEnc-mac: testProofEnc.o zkp.o util.o
	g++-10 $(MACFLAGS) -o testProofEnc util.o testProofEnc.o zkp.o -lcrypto -lssl

testProofShuffle: testProofShuffle.o zkp.o util.o
	g++ $(CFLAGS) -o testProofShuffle testProofShuffle.o util.o zkp.o -lcrypto -lssl

testProofShuffle-mac: testProofShuffle.o zkp.o util.o
	g++-10 $(MACFLAGS) -o testProofShuffle util.o testProofShuffle.o zkp.o -lcrypto -lssl

testProofMul: testProofMul.o zkp.o util.o
	g++ $(CFLAGS) -o testProofMul testProofMul.o util.o zkp.o -lcrypto -lssl
clean:
	rm -f *.o semi-honest net testzkp proofOfPTKnowledge testProofOfPTKnowledge malicious

.PHONY: clean

