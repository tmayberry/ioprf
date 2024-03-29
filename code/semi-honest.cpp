#include <stdio.h>
#include "ecioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <string.h>

#include "emp-tool/emp-tool.h"
#include <iostream>

using namespace std;
using namespace emp;

int testOPRF(char * input, NetIO * io, int party) {
    int ell = strlen(input);

    int * x = (int *) malloc(sizeof(int) * ell);

    for(int i = 0; i < ell; i++) {
        x[i] = input[i] == '1' ? 1 : 0;
    }

    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;

    if (readParameterFile(&group, &g1, &g2, ctx)==-1) {
        printf("Could not load parameter file.\n");
        return -1;
    }

    int runs = 100;
    printf("Testing PRF for input %s of length %d, %d runs\n", input, ell,runs);

    clock_t start, end;
    double cpu_time_used = 0.0;
    RECEIVERSTATE * rs;
    SENDERSTATE * ss;
    for(int z = 0; z < runs; z++)
    {

        if (party==RECEIVER) {
            rs = initializeReceiver(group, g1, g2);
            //cout <<"Receiver init done"<<endl;
        } else {
            ss = initializeSender(group, g1, g2, ell, 128);
            //cout <<"Receiver init done"<<endl;
        }

        start = clock();
        for( int y = 0; y < ell; y++) {
            if (party==RECEIVER) {
                receiverStep1(x[y], rs);
                //cout <<"Receiver Step 1 done."<<endl;

                sendPoint(io, rs->c0, rs->group, rs->ctx);
                sendPoint(io, rs->c1, rs->group, rs->ctx);
                sendPoint(io, rs->cp0, rs->group, rs->ctx);
                sendPoint(io, rs->cp1, rs->group, rs->ctx);
                sendPoint(io, rs->d0, rs->group, rs->ctx);
                sendPoint(io, rs->d1, rs->group, rs->ctx);
                sendPoint(io, rs->dp0, rs->group, rs->ctx);
                sendPoint(io, rs->dp1, rs->group, rs->ctx);
                //cout <<"Sent c, c', ... points"<<endl;

            }
            else {//sender
                //Sender receives c,c',d,d'
                EC_POINT *c0, *c1, *cp0, *cp1, *d0, *d1, *dp0, *dp1;

                receivePoint(io, &c0, ss->group, ss->ctx);
                receivePoint(io, &c1, ss->group, ss->ctx);
                receivePoint(io, &cp0, ss->group, ss->ctx);
                receivePoint(io, &cp1, ss->group, ss->ctx);
                receivePoint(io, &d0, ss->group, ss->ctx);
                receivePoint(io, &d1, ss->group, ss->ctx);
                receivePoint(io, &dp0, ss->group, ss->ctx);
                receivePoint(io, &dp1, ss->group, ss->ctx);
                //cout <<"Received points"<<endl;

                //Sender computes T, U
                senderStep1c(ss, c0, c1, cp0, cp1, d0, d1, dp0, dp1);
                //cout <<"Sender Step1c done."<<endl;

                senderStep2(ss, y);
                //cout <<"Sender Step2 done."<<endl;

                //Send X,Y to receiver
                sendPoint(io, ss->X0, ss->group, ss->ctx);
                sendPoint(io, ss->X1, ss->group, ss->ctx);
                sendPoint(io, ss->Y0, ss->group, ss->ctx);
                sendPoint(io, ss->Y1, ss->group, ss->ctx);

                //cout <<"Sent X and Y"<<endl;
            }
            if (party==RECEIVER) {
                //Receiver receives X,Y
                receivePoint(io, &(rs->X0), rs->group, rs->ctx);
                receivePoint(io, &(rs->X1), rs->group, rs->ctx);
                receivePoint(io, &(rs->Y0), rs->group, rs->ctx);
                receivePoint(io, &(rs->Y1), rs->group, rs->ctx);

                //cout <<"Received X and Y"<<endl;

                receiverStep3(x[y], rs);

                //printf("Iteration %d: ", y+1);

                //printf("iOPRF calculated by receiver: ");

                unsigned char *recprf = receiverPRF(rs);
                //printBytes(recprf, 32);
                free(recprf);

            } else {//Sender

                //printf("PRF calculated by sender: ");
                unsigned char * sendprf = senderPRF(ss, x, y+1);
                //printBytes(sendprf, 32);
                free(sendprf);

            }
            end = clock();
            cpu_time_used += (double) (end-start);

            //printBytes(sendprf, 32);
            /*	    if (memcmp(sendprf, recprf, 32)!=0) {
              printf("FAIL\n");
              } */
        }
    }

    printf("Party %d CPU time: %f ms per/IOPRF of length %d\n",party,1000.0*cpu_time_used/(CLOCKS_PER_SEC*runs), ell);


    EC_POINT_free(g1);
    EC_POINT_free(g2);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}




int main(int argc, char ** argv) {
    if (argc!=1) {
        if (strcmp(argv[1],"gen")==0) {
            createParameterFile();
            cout <<"Parameters created."<<endl;
            exit(1);
        }
    }


    if (argc!=4) {
        cout <<"You have to specify which party (1=Alice=sender or 2=Bob=receiver) and which port (e.g., 12345) you are, and the string (e.g., 101101)."<<endl;
        return -1;
    }

    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party == SENDER ? nullptr:"127.0.0.1", port);

    return testOPRF(argv[3], io, party);


}
