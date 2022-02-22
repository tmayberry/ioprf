#include <stdio.h>
#include "zkp.h"

int main(int argc, char ** argv) {
    EC_GROUP * group;
    BIGNUM * sk;
    EC_POINT * g1, *g2, *pk;

    BN_CTX * ctx = BN_CTX_new();

    generateECParameters(&group, &g1, &g2, ctx);

    sk = BN_new();
    pk = EC_POINT_new(group);
    generateECEGKey(group, g1, sk, pk, ctx);

    BIGNUM * msg = BN_new();
    bnFromInt(3, msg);

    //Test value of message
    printf("Encrypting plaintext: ");
    BN_print_fp(stdout, msg);
    printf("\n");
    //BN_zero(msg);

    //Generate encryption of 3
    EC_POINT * c = EC_POINT_new(group);
    EC_POINT * epk = EC_POINT_new(group);
    BIGNUM * r = BN_new();

    encryptECEGwithR(group, g1, g2, pk, msg, c, epk, r, ctx);

    //Generate commitment of message
    EC_POINT * com = EC_POINT_new(group);
    BIGNUM * comr = BN_new();
    commit(group, g1, g2, msg, com, comr, ctx);

    //Proof of plaintext equality

    //First step, normalize ciphertext
    zeroCiphertext(group, g2, c, msg, c, ctx);

    //Test if normalization worked
    EC_POINT * test = EC_POINT_new(group);
    EC_POINT_mul(group, test, NULL, pk, r, ctx);
    int testret = EC_POINT_cmp(group, test, c, ctx);
    printf("Normalized ciphertext is equal to zero? (should output 1)\n");
    printf("%d\n", 1-testret);


    //Prover step 1, generate rho, t1 and t2
    BIGNUM * rho = BN_new();
    EC_POINT * t1 = EC_POINT_new(group);
    EC_POINT * t2 = EC_POINT_new(group);

    proofOfEncryptionStep1(group, g1, epk, pk, c, t1, t2, rho, ctx);

    //Verifier step 2, generate the challenge e
    BIGNUM * e = BN_new();
    proofOfEncryptionStep2(group, e, ctx);

    //Prover step 3, generate s
    BIGNUM * s = BN_new();
    proofOfEncryptionStep3(group, e, rho, r, s, ctx);

    //Verifier step 4, accept if all arguments correct
    int ret = proofOfEncryptionStep4(group, g1, epk, pk, c, s, e, t1, t2, ctx);

    printf("Testing proof of plaintext (should output 1)\n");
    printf("%d\n", ret);

    //Proof of knowledge test

    EC_POINT * t = EC_POINT_new(group);
    BIGNUM * rho1 = BN_new();
    BIGNUM * rho2 = BN_new();

    proofOfKnowledgeStep1(group, g1, g2, rho1, rho2, t, ctx);

    proofOfKnowledgeStep2(group, e, ctx);

    BIGNUM * s1 = BN_new();
    BIGNUM * s2 = BN_new();

    proofOfKnowledgeStep3(group, rho1, rho2, e, comr, s1, s2, msg, ctx);

    ret = proofOfKnowledgeStep4(group, g1, g2, s1, s2, com, e, t, ctx);

    printf("Testing proof of knowledge of plaintext\n");
    printf("%d\n", ret);

    return 0;
}
