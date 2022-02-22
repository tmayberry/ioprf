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


    printf("Testing proof of shuffle\n");

    if (party == RECEIVER) {
        BIGNUM *sk = BN_new();
        BIGNUM * one = BN_new();
        BN_one(one);
        EC_POINT *pk = EC_POINT_new(group);
        generateECEGKey(group, g1, sk, pk, ctx);

        //First need the inputs, ciphertext c1 = (A, B) and c2 = (C, D) which is a shuffling and reencryption of c1
        //Need a commitment to x which determines if (C,D) is a reencryption of c1 or not
        //Also need a commitment to x, the r value used in the commitment, and the rprime used in reencryption C and D

        BIGNUM * bnx = BN_new();
        EC_POINT * A = EC_POINT_new(group);
        EC_POINT * B = EC_POINT_new(group);
        EC_POINT * C = EC_POINT_new(group);
        EC_POINT * D = EC_POINT_new(group);
        BIGNUM * rprime = BN_new();
        BIGNUM * r2 = BN_new();

        //Commit to x, r is the random value used for the commitment
        int x = 1;
        bnFromInt(x, bnx);

        EC_POINT * com = EC_POINT_new(group);
        BIGNUM * r = BN_new();
        commit(group, g1, g2, bnx, com, r, ctx);

        //Encrypt some ciphertext, store in (A,B)
        //rprime is the random value used for this encryption
        encryptECEGwithR(group, g1, g2, pk, one, B, A, r2, ctx);

        //Do some shuffle
        //Sample rprime as part of the shuffle
        randomBNFromECGroup(group, rprime, ctx);
        EC_POINT_mul(group, C, NULL, g1, rprime, ctx);
        if( x == 1 )
            EC_POINT_add(group, C, C, A, ctx);

        EC_POINT_mul(group, D, NULL, pk, rprime, ctx);
        if( x == 1 )
            EC_POINT_add(group, D, D, B, ctx);

        //Ok, we have all the pieces now
        //Need temporary variables (some were already declared above but I will repeat here for migrating later)
        BIGNUM * rho1 = BN_new();
        BIGNUM * rho2 = BN_new();
        BIGNUM * rho3 = BN_new();
        EC_POINT * t1 = EC_POINT_new(group);
        EC_POINT * t2 = EC_POINT_new(group);
        EC_POINT * t3 = EC_POINT_new(group);
        BIGNUM * e = BN_new();
        BIGNUM * s1 = BN_new();
        BIGNUM * s2 = BN_new();
        BIGNUM * s3 = BN_new();

        //If receiver
        proofOfShuffleStep1(group, g1, g2, pk, A, B, t1, t2, t3, rho1, rho2, rho3, ctx);

        //send A,B,C,D
        sendPoint(io, pk, group, ctx);
        sendPoint(io, com, group, ctx);

        sendPoint(io, A, group, ctx);
        sendPoint(io, B, group, ctx);
        sendPoint(io, C, group, ctx);
        sendPoint(io, D, group, ctx);


        //Send t1, t2, t3, to sender
        sendPoint(io, t1, group, ctx);
        sendPoint(io, t2, group, ctx);
        sendPoint(io, t3, group, ctx);

        receiveBN(io, e);

        //If receiver
        proofOfShuffleStep3(group, rho1, rho2, rho3, e, x, r, rprime, s1, s2, s3, ctx);

        //Send s1, s2, s3 to sender
        sendBN(io, s1);
        sendBN(io, s2);
        sendBN(io, s3);

    } else { //SENDER
        EC_POINT *t1, *t2, *t3, *A, *B, *C, *D, *pk, *com;
        receivePoint(io, &pk, group, ctx);
        receivePoint(io, &com, group, ctx);
        receivePoint(io, &A, group, ctx);
        receivePoint(io, &B, group, ctx);
        receivePoint(io, &C, group, ctx);
        receivePoint(io, &D, group, ctx);

        receivePoint(io, &t1, group, ctx);
        receivePoint(io, &t2, group, ctx);
        receivePoint(io, &t3, group, ctx);

        //If sender
        BIGNUM * e = BN_new();
        proofOfShuffleStep2(group, e, ctx);

        //Send e to receiver
        sendBN(io, e);

        BIGNUM * s1 = BN_new();
        BIGNUM * s2 = BN_new();
        BIGNUM * s3 = BN_new();

        receiveBN(io, s1);
        receiveBN(io, s2);
        receiveBN(io, s3);
        //If sender
        int ret = proofOfShuffleStep4(group, g1, g2, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com, ctx);

        printf("%d\n", ret);

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
