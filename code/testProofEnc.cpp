#include "zkp.h"

using namespace std;

void testSingleProof(NetIO *io, int party) {
    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;

    if (readParameterFile(&group, &g1, &g2, ctx)!=0) {
        printf("Problem with parameter file\n");
    }
    if (party == RECEIVER) {
        //Generate Elgamal key
        BIGNUM *sk = BN_new();
        EC_POINT *pk = EC_POINT_new(group);
        generateECEGKey(group, g1, sk, pk, ctx);

        //Generate encryption of 3
        BIGNUM * msg = BN_new();
        bnFromInt(0, msg);
        EC_POINT * c = EC_POINT_new(group);
        EC_POINT * epk = EC_POINT_new(group);
        BIGNUM * r_enc = BN_new();
        encryptECEGwithR(group, g1, g2, pk, msg, c, epk, r_enc, ctx);

        sendPoint(io, pk, group, ctx);
        sendPoint(io, epk, group, ctx);
        sendPoint(io, c, group, ctx);

        cout <<proveEnc(io, pk, epk, c, r_enc, msg, group, g1, g2, ctx)<<endl;

    } else { //SENDER

        BIGNUM * msg = BN_new();
        bnFromInt(0, msg);

        EC_POINT *pk, *epk, *c;
        receivePoint(io, &pk, group, ctx);
        receivePoint(io, &epk, group, ctx);
        receivePoint(io, &c, group, ctx);
        cout <<verifyEnc(io, pk, epk, c, msg, group, g1, g2, ctx)<<endl;

        EC_POINT_free(pk);
        EC_POINT_free(epk);
        EC_POINT_free(c);
        BN_free(msg);
    }

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


