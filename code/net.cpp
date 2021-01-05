#include "emp-tool/emp-tool.h"
#include <iostream>
using namespace std;
using namespace emp;

void mySend(NetIO * io, const void *data, size_t length) {
  io->send_data(&length, sizeof(length));
  io->send_data(data, length);
}

void myRecv(NetIO * io, void **data, size_t *length) {
  io->recv_data(length, sizeof(size_t));
  *data = (void *) malloc(*length);
  io->recv_data(*data, *length);
}


int main(int argc, char** argv) {
  if (argc!=3) {
    cout <<"You have to specify which party (1=Alice=sender or 2=Bob=receiver) and which port you are."<<endl;
    return -1;
  }
  
  int port, party;
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party == ALICE ? nullptr:"127.0.0.1", port);

     
  if (party == ALICE) {
    mySend(io, "blabla", strlen("blabla"));
  } else {
    char *buffer;
    size_t length;
    myRecv(io, (void **)&buffer, &length);
    cout <<"Received "<<length<<" Bytes: "<<buffer<<endl;
  }
  
  return 0;
}
