#include <stdio.h>
#include "zkp.h"

int main(int argc, char ** argv){
    EC_GROUP * group;
    BIGNUM * sk;
    EC_POINT * g1, *g2, *pk;

    BN_CTX * ctx = BN_CTX_new();

    generateECParameters(&group, &g1, &g2, ctx);

    sk = BN_new();
    pk = EC_POINT_new(group);
    generateECEGKey(group, g1, sk, pk, ctx);

    BIGNUM * msg = BN_new();
    bnFromInt(1, msg);

    //Test value of message
    printf("Encrypting plaintext:");
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

    //Proof of plaintext bit
    c = EC_POINT_new(group);
    BIGNUM * e1 = BN_new();
    BIGNUM * e2 = BN_new();
    BIGNUM * rhop = BN_new();


    printf("Testing proof of plaintext bit\n");


    //Plaintext value of bit encryption
    int x = 1;
    bnFromInt(x, msg);

    commit(group, g1, g2, msg, c, r, ctx);
    //encryptECEGwithR(group, g1, g2, pk, msg, c, epk, r, ctx);

    //If receiver
    proofOfPlaintextBitStep1(group, g1, g2, x, c, e1, e2, rho, rhop, t1, t2, ctx);

    //Send t1, t2, c1, c2 to sender

    //If sender
    proofOfPlaintextBitStep2(group, e, ctx);

    //Send e to receiver

    //If receiver
    proofOfPlaintextBitStep3(group, x, e1, e, rho, rhop, r, e2, s1, s2, ctx);

    //Send e1, e2, e, s1, s2 to sender

    ret = proofOfPlaintextBitStep4(group, g1, g2, e, e1, e2, s1, s2, t1, t2, c, ctx);

    printf("%d\n", ret);

    //**********************************************
    //Proof of shuffle
    //**********************************************

    printf("Testing proof of shuffle\n");

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
    x = 1;
    bnFromInt(x, bnx);
    commit(group, g1, g2, bnx, com, r, ctx);

    //Encrypt some ciphertext, store in (A,B)
    //rprime is the random value used for this encryption
    encryptECEGwithR(group, g1, g2, pk, msg, B, A, r2, ctx);

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
    //BIGNUM * rho1 = BN_new();
    //BIGNUM * rho2 = BN_new();
    BIGNUM * rho3 = BN_new();
    //EC_POINT * t1 = EC_POINT_new(group);
    //EC_POINT * t2 = EC_POINT_new(group);
    EC_POINT * t3 = EC_POINT_new(group);
    //BIGNUM * e = BN_new():
    //BIGNUM * s1 = BN_new();
    //BIGNUM * s2 = BN_new();
    BIGNUM * s3 = BN_new();

    //If receiver
    proofOfShuffleStep1(group, g1, g2, pk, A, B, t1, t2, t3, rho1, rho2, rho3, ctx);

    //Send t1, t2, t3, to sender

    //If sender
    proofOfShuffleStep2(group, e, ctx);

    //Send e to receiver

    //If receiver
    proofOfShuffleStep3(group, rho1, rho2, rho3, e, x, r, rprime, s1, s2, s3, ctx);

    //Send s1, s2, s3 to sender

    //If sender
    ret = proofOfShuffleStep4(group, g1, g2, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com, ctx);

    printf("%d\n", ret);

    //**********************************************
    //Proof of multiplication
    //**********************************************
    //Need a commitment to x, the value that is being multiplied by
    //Then, prove that (C, D) is an encryption of (A^x, B^x)

    //Need temporary variables (already declared above but I will repeat here for migrating later)
    //BIGNUM * rho1 = BN_new();
    //BIGNUM * rho2 = BN_new();
    //EC_POINT * t1 = EC_POINT_new(group);
    //EC_POINT * t2 = EC_POINT_new(group);
    //EC_POINT * t3 = EC_POINT_new(group);
    //BIGNUM * e = BN_new():
    //BIGNUM * s1 = BN_new();
    //BIGNUM * s2 = BN_new();
    
    printf("Testing proof of multiplication\n");

    x = 200;
    bnFromInt(x, bnx);

    commit(group, g1, g2, bnx, com, r, ctx);

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
    ret = proofOfMultiplicationStep4(group, g1, g2, A, B, C, D, s1, s2, t1, t2, t3, e, com, ctx);
    
    printf("%d\n", ret);

    return 0;
}

