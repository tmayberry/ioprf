#include "zkp.h"

using namespace std;

void testParallelProof(NetIO * io, int party, int n) {
    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;


    if (readParameterFile(&group, &g1, &g2, ctx)!=0) {
        printf("Problem with parameter file\n");
    }

    printf("Testing %d parallel proofs of knowledge of plaintext\n", n);
    int ret;

    if (party == PROVER) { //PROVER

        BIGNUM ** msg = (BIGNUM **) malloc(n*sizeof(BIGNUM*));
        EC_POINT ** com= (EC_POINT **) malloc(n*sizeof(EC_POINT *));
        BIGNUM ** comr = (BIGNUM **) malloc(n*sizeof(BIGNUM*));

        for (int i = 0; i<n; i++) {
            msg[i] = BN_new();
            bnFromInt(i, msg[i]);


            //Generate commitment of message
            com[i] = EC_POINT_new(group);
            comr[i] = BN_new();
            commit(group, g1, g2, msg[i], com[i], comr[i], ctx);

            //Send commitment
            sendPoint(io, com[i], group, ctx);
        }
        ret = parallelProofOfPTKnowledge(io, ctx, group, g1, g2, PROVER, com, msg, comr, n);

        for (int i = 0; i<n; i++) {
            BN_free(msg[i]);
            BN_free(comr[i]);
            EC_POINT_free(com[i]);
        }
        free(msg);
        free(comr);
        free(com);

    } else { //Verifier
        EC_POINT ** com = (EC_POINT **) malloc(n*sizeof(EC_POINT **));
        for (int i = 0; i<n; i++) {
            //Receive commitment
            receivePoint(io, &(com[i]), group, ctx);
        }
        ret = parallelProofOfPTKnowledge(io, ctx, group, g1, g2, VERIFIER, com, NULL, NULL,n);
        for (int i = 0; i<n; i++) {
            EC_POINT_free(com[i]);
        }
        free(com);

        printf("Verifier: %d\n", ret);
    }


}


void testSingleProof(NetIO * io, int party) {
    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;


    if (readParameterFile(&group, &g1, &g2, ctx)!=0) {
        printf("Problem with parameter file\n");
    }

    printf("Testing single proof of knowledge of plaintext\n");
    int ret;

    if (party == SENDER) { //PROVER

        BIGNUM * msg = BN_new();
        bnFromInt(3, msg);

        //Generate commitment of message
        EC_POINT * com = EC_POINT_new(group);
        BIGNUM * comr = BN_new();
        commit(group, g1, g2, msg, com, comr, ctx);

        //Send commitment
        sendPoint(io, com, group, ctx);

        ret = proofOfPTKnowledge(io, ctx, group, g1, g2, PROVER, com, msg, comr);

        BN_free(comr);
        BN_free(msg);
        EC_POINT_free(com);
    } else { //Verifier
        EC_POINT * com;
        //Receive commitment
        receivePoint(io, &com, group, ctx);

        ret = proofOfPTKnowledge(io, ctx, group, g1, g2, VERIFIER, com, NULL, NULL);
        EC_POINT_free(com);
        printf("Verifier: %d\n", ret);
    }


}

int main(int argc, char ** argv) {
    cout <<"Don't forget to also specify the number of rounds."<<endl;
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party == SENDER ? nullptr:"127.0.0.1", port);

    testSingleProof(io, party);
    testParallelProof(io, party, atoi(argv[3]));
    return 0;


}
