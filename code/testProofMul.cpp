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

    if (party==PROVER) {
    } else { //VERIFIER

    }
    BIGNUM *sk = BN_new();
    EC_POINT *pk = EC_POINT_new(group);
    generateECEGKey(group, g1, sk, pk, ctx);

    EC_POINT * A = EC_POINT_new(group);
    EC_POINT * B = EC_POINT_new(group);
    EC_POINT * C = EC_POINT_new(group);
    EC_POINT * D = EC_POINT_new(group);
    EC_POINT * com = EC_POINT_new(group);
    BIGNUM *bnx = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *r2 = BN_new();

    bnFromInt(300, bnx);
    //Encrypt some ciphertext, store in (A,B)
    //rprime is the random value used for this encryption
    encryptECEGwithR(group, g1, g2, pk, bnx, B, A, r2, ctx);

    //Commitment to x
    int x = 200;
    bnFromInt(x, bnx);
    commit(group, g1, g2, bnx, com, r, ctx);

    //Need temporary variables (already declared above but I will repeat here for migrating later)
    BIGNUM * rho1 = BN_new();
    BIGNUM * rho2 = BN_new();
    EC_POINT * t1 = EC_POINT_new(group);
    EC_POINT * t2 = EC_POINT_new(group);
    EC_POINT * t3 = EC_POINT_new(group);
    BIGNUM * e = BN_new();
    BIGNUM * s1 = BN_new();
    BIGNUM * s2 = BN_new();

    printf("Testing proof of multiplication\n");

    EC_POINT_mul(group, C, NULL, A, bnx, ctx);
    EC_POINT_mul(group, D, NULL, B, bnx, ctx);

    //If sender
    proofOfMultiplicationStep1(group, g1, g2, A, B, t1, t2, t3, rho1, rho2, ctx);

    //Send t1, t2, t3, to receiver

    //If receiver
    proofOfMultiplicationStep2(group, e, ctx);
    //Send e to sender

    //If sender
    proofOfMultiplicationStep3(group, rho1, rho2, e, bnx, r, s1, s2, ctx);
    //Send s1, s2 to receiver

    //If receiver
    int ret = proofOfMultiplicationStep4(group, g1, g2, A, B, C, D, s1, s2, t1, t2, t3, e, com, ctx);

    printf("%d\n", ret);



}

int main(int argc, char ** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party == SENDER ? nullptr:"127.0.0.1", port);

    testSingleProof(io, party);
    return 0;


}


