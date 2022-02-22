#include "zkp.h"

using namespace std;

void testSingleProof(NetIO * io, int party) {
    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;


    if (readParameterFile(&group, &g1, &g2, ctx)!=0) {
        printf("Problem with parameter file\n");
    }

    if (party == RECEIVER) {

        BIGNUM * msg = BN_new();
        //Plaintext value of bit encryption
        int x = 0;
        bnFromInt(x, msg);

        BIGNUM * r = BN_new();
        EC_POINT * com = EC_POINT_new(group);
        commit(group, g1, g2, msg, com, r, ctx);

        cout <<proveBit(io, x, com, r, group, g1, g2, ctx)<<endl;

        BN_free(r);
        BN_free(msg);
        EC_POINT_free(com);

    } else { //SENDER
        EC_POINT *com;
        cout <<verifyBit(io, &com, group, g1, g2, ctx)<<endl;
        EC_POINT_free(com);
    }

}

void testNoNetwork() {
    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;


    if (readParameterFile(&group, &g1, &g2, ctx)!=0) {
        printf("Problem with parameter file\n");
    }


    printf("Testing proof of plaintext bit\n");

    BIGNUM * msg = BN_new();
    //Plaintext value of bit encryption
    int x = 0;
    bnFromInt(x, msg);

    BIGNUM * r = BN_new();
    EC_POINT * com = EC_POINT_new(group);
    commit(group, g1, g2, msg, com, r, ctx);

    //If receiver
    BIGNUM * e1 = BN_new();
    BIGNUM * e2 = BN_new();
    BIGNUM * rho = BN_new();
    BIGNUM * rhop = BN_new();
    EC_POINT * t1 = EC_POINT_new(group);
    EC_POINT * t2 = EC_POINT_new(group);
    BIGNUM * s1 = BN_new();
    BIGNUM * s2 = BN_new();
    BIGNUM * e = BN_new();
    proofOfPlaintextBitStep1(group, g1, g2, x, com, e1, e2, rho, rhop, t1, t2, ctx);

    //Send t1, t2, com sender

    //If sender
    proofOfPlaintextBitStep2(group, e, ctx);

    //Send e to receiver

    //If receiver
    proofOfPlaintextBitStep3(group, x, e1, e, rho, rhop, r, e2, s1, s2, ctx);

    //Send e1, e2, e, s1, s2 to sender

    int ret = proofOfPlaintextBitStep4(group, g1, g2, e, e1, e2, s1, s2, t1, t2, com, ctx);

    printf("%d\n", ret);

    BN_free(s1);
    BN_free(s2);
    BN_free(rho);
    BN_free(rhop);
    BN_free(e1);
    BN_free(e2);
    BN_free(e);
    BN_free(r);
    BN_free(msg);

    EC_POINT_free(com);
    EC_POINT_free(t1);
    EC_POINT_free(t2);

}


int main(int argc, char ** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party == SENDER ? nullptr:"127.0.0.1", port);

    /*    cout <<"Without network"<<endl;
    testNoNetwork();
    cout <<"With network"<<endl;*/
    testSingleProof(io, party);
    return 0;


}

