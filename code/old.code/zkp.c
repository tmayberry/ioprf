#include "zkp.h"

//Computes Pedersen commitment for message m, stores output in c and r
void commit(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * m, EC_POINT * com, BIGNUM * r, BN_CTX * ctx){
    randomBNFromECGroup(group, r, ctx);
    EC_POINT * temp = EC_POINT_new(group);

    EC_POINT_mul(group, temp, NULL, g, m, ctx);
    EC_POINT_mul(group, com, NULL, g1, r, ctx);

    EC_POINT_add(group, com, com, temp, ctx);

    EC_POINT_free(temp);
}

//Verifies Pedersen commitment 
int verifyCommitment(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * m, EC_POINT * c, BIGNUM * r, BN_CTX * ctx){
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);

    EC_POINT_mul(group, temp1, NULL, g, m, ctx);
    EC_POINT_mul(group, temp2, NULL, g1, r, ctx);

    EC_POINT_add(group, temp1, temp2, temp1, ctx);

    int cmp = EC_POINT_cmp(group, temp1, c, ctx);

    EC_POINT_free(temp1);
    EC_POINT_free(temp2);

    if(cmp == 0)
        return 1;
    return 0;
}

//Zeroes the ciphertext c (adds g2*-m) for use in a plaintext ZKP, stores encryption of zero in c2
void zeroCiphertext(EC_GROUP * group, EC_POINT * g2, EC_POINT * c, BIGNUM * msg, EC_POINT * c2, BN_CTX * ctx){
    EC_POINT * temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, NULL, g2, msg, ctx);
    EC_POINT_invert(group, temp, ctx);
    EC_POINT_add(group, c2, temp, c, ctx);
    EC_POINT_free(temp);
}

//Prover first step of proof of plaintext
//Inputs: group, u1, u2, u3, u4
//Outputs: rho, t1, t2
void proofOfEncryptionStep1(EC_GROUP * group, EC_POINT * u1, EC_POINT * u2, EC_POINT * u3, EC_POINT * u4, EC_POINT * t1, EC_POINT * t2, BIGNUM * rho, BN_CTX * ctx){
    //Choose random rho in Z_p
    randomBNFromECGroup(group, rho, ctx);

    EC_POINT_mul(group, t1, NULL, u1, rho, ctx);
    EC_POINT_mul(group, t2, NULL, u3, rho, ctx);
}

//Verifier second step of proof of plaintext
//Inputs: group
//Outputs: e
void proofOfEncryptionStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx){
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of plaintext
//Inputs: group, e, rho, r
//Outputs: s
void proofOfEncryptionStep3(EC_GROUP * group, BIGNUM * e, BIGNUM * rho, BIGNUM * r, BIGNUM * s, BN_CTX * ctx){
    BIGNUM * order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BN_mod_mul(s, e, r, order, ctx);
    BN_mod_add(s, s, rho, order, ctx);

    BN_free(order);
}

//Verifier fourth step of proof of plaintext
//Inputs: group, u1, u2, u3, u4, s, e, t1, t2
//Return: 1 if verifies successfully, 0 if not
int proofOfEncryptionStep4(EC_GROUP * group, EC_POINT * u1, EC_POINT * u2, EC_POINT * u3, EC_POINT * u4, BIGNUM * s, BIGNUM * e, EC_POINT * t1, EC_POINT * t2, BN_CTX * ctx){
    EC_POINT * left1, * right1, * left2, * right2;
    left1 = EC_POINT_new(group);
    left2 = EC_POINT_new(group);
    right1 = EC_POINT_new(group);
    right2 = EC_POINT_new(group);

    EC_POINT_mul(group, left1, NULL, u1, s, ctx);
    
    EC_POINT_mul(group, right1, NULL, u2, e, ctx);
    EC_POINT_add(group, right1, right1, t1, ctx);

    EC_POINT_mul(group, left2, NULL, u3, s, ctx);

    EC_POINT_mul(group, right2, NULL, u4, e, ctx);
    EC_POINT_add(group, right2, right2, t2, ctx);

    int firstcmp = EC_POINT_cmp(group, left1, right1, ctx);
    int secondcmp = EC_POINT_cmp(group, left2, right2, ctx);

    if(firstcmp == 0 && secondcmp == 0)
        return 1;
    return 0;
}

//Prover first step of proof of knowledge of plaintext
//Inputs: group, g1, g
//Outputs: rho1, rho2, t
void proofOfKnowledgeStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * rho1, BIGNUM * rho2, EC_POINT * t, BN_CTX * ctx){
    EC_POINT * temp = EC_POINT_new(group);

    randomBNFromECGroup(group, rho1, ctx);
    randomBNFromECGroup(group, rho2, ctx);

    EC_POINT_mul(group, temp, NULL, g, rho2, ctx);
    EC_POINT_mul(group, t, NULL, g1, rho1, ctx);
    EC_POINT_add(group, t, temp, t, ctx);

    EC_POINT_free(temp);
}

//Verifier second step of proof of knowledge of plaintext
//Inputs: group
//Outputs: e
void proofOfKnowledgeStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx){
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of knowledge of plaintext
//Inputs: group, rho1, rho2, e, r, m
//Outputs: s1, s2
void proofOfKnowledgeStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * e, BIGNUM * r, BIGNUM * s1, BIGNUM * s2, BIGNUM * m, BN_CTX * ctx){
    BN_mul(s1, e, r, ctx);
    BN_add(s1, s1, rho1);

    BN_mul(s2, e, m, ctx);
    BN_add(s2, s2, rho2);
}

//Prover third step of proof of knowledge of plaintext
//Inputs: group, g1, g, s1, s2, com, e, t
//Returns: 1 if verification successful, 0 if not
int proofOfKnowledgeStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * s1, BIGNUM * s2, EC_POINT * com, BIGNUM * e, EC_POINT * t, BN_CTX * ctx){
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);

    EC_POINT_mul(group, temp1, NULL, g1, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, g, s2, ctx);
    EC_POINT_mul(group, temp3, NULL, com, e, ctx);
    EC_POINT_add(group, temp3, temp3, t, ctx);
    EC_POINT_add(group, temp1, temp1, temp2, ctx);

    int ret = EC_POINT_cmp(group, temp1, temp3, ctx);


    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);

    if(ret == 0){
        return 1;
    }
    return 0;
}

//Prover first step of proof of plaintext bit
//Behaves differently depending on if x == 0 or 1, the unknown half of the ZKP is "faked"
//c is the commitment value, could be 0 or 1 depending on x
//Inputs: group, g1, g, x, c
//Outputs: c2, r2, e1, rho, rhop, t1, t2
void proofOfPlaintextBitStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, unsigned int x, EC_POINT * c,  BIGNUM * e1, BIGNUM * e2, BIGNUM * rho, BIGNUM * rhop, EC_POINT * t1, EC_POINT * t2, BN_CTX * ctx){
    randomBNFromECGroup(group, rho, ctx);
    randomBNFromECGroup(group, rhop, ctx);

    EC_POINT * temp = EC_POINT_new(group);

    if( x == 1 ){
        randomBNFromECGroup(group, e2, ctx);
        
        //Generate correct commitment for x = 1
        EC_POINT_mul(group, t1, NULL, g1, rho, ctx);

        //Multiply by the fabricated challenge
        EC_POINT_mul(group, t2, NULL, c, e2, ctx);
        //Invert
        EC_POINT_invert(group, t2, ctx);

        //Finish commitment
        EC_POINT_mul(group, temp, NULL, g1, rhop, ctx);
        EC_POINT_add(group, t2, temp, t2, ctx);
    }  
    else{
        randomBNFromECGroup(group, e1, ctx);
        //Fake commitment for x = 1
        //Invert g (necessary to zero out commitment of 1)
        EC_POINT_copy(t1, g);
        EC_POINT_invert(group, t1, ctx);

        //Add g^-1 to c
        EC_POINT_add(group, t1, t1, c, ctx);

        //Calculate ^e1
        EC_POINT_mul(group, t1, NULL, t1, e1, ctx);
        //Invert (because we want -e1)
        EC_POINT_invert(group, t1, ctx);

        //Create proof commitment and add to t1
        EC_POINT_mul(group, temp, NULL, g1, rho, ctx);
        EC_POINT_add(group, t1, temp, t1, ctx);

        //Generate correct commitment for x = 0
        EC_POINT_mul(group, t2, NULL, g1, rhop, ctx);
    }

    EC_POINT_free(temp);
}

//Verifier second step of proof of plaintext bit
//Inputs: group
//Outputs: e
void proofOfPlaintextBitStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx){
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of plaintext bit
//Inputs: group, g1, e1, e, rho, r
//Outputs: e2, s1
void proofOfPlaintextBitStep3(EC_GROUP * group, unsigned int x, BIGNUM * e1, BIGNUM * e, BIGNUM * rho, BIGNUM * rhop, BIGNUM * r, BIGNUM * e2, BIGNUM * s1, BIGNUM * s2, BN_CTX * ctx){
    BIGNUM * order = BN_new();
    EC_GROUP_get_order(group, order, ctx);
    

    if( x == 1 ){
        BN_mod_sub(e1, e, e2, order, ctx);

        BN_mod_mul(s1, e1, r, order, ctx);
        BN_mod_add(s1, s1, rho, order, ctx);

        BN_copy(s2, rhop);
    }
    else{
        BN_mod_sub(e2, e, e1, order, ctx);

        BN_mod_mul(s2, e2, r, order, ctx);
        BN_mod_add(s2, s2, rhop, order, ctx);

        BN_copy(s1, rho);
    }

    BN_free(order);
}

//Verifier fourth step of proof of plaintext bit
//Inputs: group, g1, x, c
//Returns: 1 if verifies successfully
int proofOfPlaintextBitStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * e, BIGNUM * e1, BIGNUM * e2, BIGNUM * s1, BIGNUM * s2, EC_POINT * t1, EC_POINT * t2, EC_POINT * c, BN_CTX * ctx){
    BIGNUM * temp = BN_new();
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);
    BIGNUM * order = BN_new();

    int retval = 1;

    EC_GROUP_get_order(group, order, ctx);

    BN_mod_add(temp, e1, e2, order, ctx);
    int cmp = BN_cmp(e, temp);

    if(cmp != 0){
        printf("Cmp 1 failed\n");
        retval = 0;
    }

    EC_POINT_copy(temp1, g);
    EC_POINT_invert(group, temp1, ctx);
    EC_POINT_add(group, temp1, temp1, c, ctx);

    EC_POINT_mul(group, temp1, NULL, temp1, e1, ctx);
    EC_POINT_add(group, temp1, temp1, t1, ctx);

    EC_POINT_mul(group, temp2, NULL, g1, s1, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp2, ctx);

    if(cmp != 0){
        printf("Cmp 2 failed\n");
        retval = 0;
    }

    EC_POINT_mul(group, temp1, NULL, c, e2, ctx);
    EC_POINT_add(group, temp1, temp1, t2, ctx);

    EC_POINT_mul(group, temp2, NULL, g1, s2, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp2, ctx);   

    if(cmp != 0){
        printf("Cmp 3 failed\n");
        retval = 0;
    }

    BN_free(temp);
    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);
    BN_free(order);

    return retval;
}

//Prover first step of proof of shuffle
//Inputs: group, g1, g2, pk, A, B
//Outputs: t1, t2, t3, rho1, rho2, rho3
void proofOfShuffleStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * pk, EC_POINT * A, EC_POINT * B, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * rho3, BN_CTX * ctx){
    EC_POINT * temp = EC_POINT_new(group);

    randomBNFromECGroup(group, rho1, ctx);
    randomBNFromECGroup(group, rho2, ctx);
    randomBNFromECGroup(group, rho3, ctx);

    //t1 = g^rho1 * A^rho2
    EC_POINT_mul(group, t1, NULL, g1, rho1, ctx);
    EC_POINT_mul(group, temp, NULL, A, rho2, ctx);
    EC_POINT_add(group, t1, temp, t1, ctx);

    //t2 = pk^rho1 * B^rho2
    EC_POINT_mul(group, t2, NULL, pk, rho1, ctx);
    EC_POINT_mul(group, temp, NULL, B, rho2, ctx);
    EC_POINT_add(group, t2, t2, temp, ctx);

    //t3 = g1^rho3 * g^rho2
    EC_POINT_mul(group, t3, NULL, g1, rho3, ctx);
    EC_POINT_mul(group, temp, NULL, g, rho2, ctx);
    EC_POINT_add(group, t3, temp, t3, ctx);

    EC_POINT_free(temp);
}

//Verifier second step of proof of shuffle
//Inputs: group
//Outputs: e
void proofOfShuffleStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx){
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of shuffle
//Inputs: group, rho1, rho2, rho3, e, x, r, rprime
//Outputs: s1, s2, s3
void proofOfShuffleStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * rho3, BIGNUM * e, unsigned int x, BIGNUM * r, BIGNUM * rprime, BIGNUM * s1, BIGNUM * s2, BIGNUM * s3, BN_CTX * ctx){
    BIGNUM * temp = BN_new();
    BIGNUM * order = BN_new();

    EC_GROUP_get_order(group, order, ctx);

    //s1 = rho1 + e * rprime
    BN_mod_mul(temp, e, rprime, order, ctx);
    BN_mod_add(s1, rho1, temp, order, ctx);

    //s2 = rho2 + e*x
    BN_zero(temp);
    if(x != 0)
        BN_copy(temp, e);
    BN_mod_add(s2, rho2, temp, order, ctx);


    //s3 = rho3 + e * r
    BN_mod_mul(temp, e, r, order, ctx);
    BN_mod_add(s3, rho3, temp, order, ctx);

    BN_free(order);
    BN_free(temp);
}

//Verifier fourth step of proof of shuffle
//Inputs: group, g1, g, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com
//Returns: 1 if verifies successfully
int proofOfShuffleStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * pk, EC_POINT * A, EC_POINT * B, EC_POINT * C, EC_POINT * D, BIGNUM * s1, BIGNUM * s2, BIGNUM * s3, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * e, EC_POINT * com, BN_CTX * ctx){
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);

    int ret = 1;

    //Check if g1^s2 * A^s2 = C^e * t1
    EC_POINT_mul(group, temp1, NULL, A, s2, ctx);
    EC_POINT_mul(group, temp2, NULL, g1, s1, ctx);
    EC_POINT_add(group, temp1, temp1, temp2, ctx);

    EC_POINT_mul(group, temp3, NULL, C, e, ctx);
    EC_POINT_add(group, temp3, temp3, t1, ctx);

    int cmp = EC_POINT_cmp(group, temp1, temp3, ctx);
    if( cmp != 0 ){
        printf("Failed cmp 1\n");
        ret = 0;
    }

    //Check if pk^s1 * B^s2 = D ^ e * t2
    EC_POINT_mul(group, temp1, NULL, pk, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, B, s2, ctx);
    EC_POINT_add(group,temp1, temp1, temp2, ctx);
    
    EC_POINT_mul(group, temp3, NULL, D, e, ctx);
    EC_POINT_add(group, temp3, temp3, t2, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp3, ctx);
    if( cmp != 0 ){
        printf("Failed cmp 2\n");
        ret = 0;
    }

    //Check if g1^s3 * g^s2 = com^e * t3
    EC_POINT_mul(group, temp1, NULL, g1, s3, ctx);
    EC_POINT_mul(group, temp2, NULL, g, s2, ctx);
    EC_POINT_add(group,temp1, temp1, temp2, ctx);
    
    EC_POINT_mul(group, temp3, NULL, com, e, ctx);
    EC_POINT_add(group, temp3, temp3, t3, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp3, ctx);
    if( cmp != 0 ){
        printf("Failed cmp 3\n");
        ret = 0;
    }

    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);

    return ret;
}

//Prover first step of proof of shuffle
//Inputs: group, g1, g2, A, B
//Outputs: t1, t2, t3, rho1, rho2
void proofOfMultiplicationStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * A, EC_POINT * B, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * rho1, BIGNUM * rho2, BN_CTX * ctx){
    EC_POINT * temp = EC_POINT_new(group);

    randomBNFromECGroup(group, rho1, ctx);
    randomBNFromECGroup(group, rho2, ctx);

    //t1 = A^rho1
    EC_POINT_mul(group, t1, NULL, A, rho1, ctx);

    //t2 = B^rho2
    EC_POINT_mul(group, t2, NULL, B, rho1, ctx);

    //t3 = g1^rho2 * g^rho1
    EC_POINT_mul(group, temp, NULL, g, rho1, ctx);
    EC_POINT_mul(group, t3, NULL, g1, rho2, ctx);
    EC_POINT_add(group, t3, t3, temp, ctx);


    EC_POINT_free(temp);
}

//Verifier second step of proof of shuffle
//Inputs: group
//Outputs: e
void proofOfMultiplicationStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx){
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of shuffle
//Inputs: group, rho1, rho2, e, x, r
//Outputs: s1, s2
void proofOfMultiplicationStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * e, BIGNUM * x, BIGNUM * r, BIGNUM * s1, BIGNUM * s2, BN_CTX * ctx){
    
    BIGNUM * order = BN_new();

    EC_GROUP_get_order(group, order, ctx);

    BN_mod_mul(s1, e, x, order, ctx);
    BN_mod_add(s1, rho1, s1, order, ctx);

    BN_mod_mul(s2, e, r, order, ctx);
    BN_mod_add(s2, s2, rho2, order, ctx);

    BN_free(order);
}

//Verifier fourth step of proof of shuffle
//Inputs: group, g1, g, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com
//Returns: 1 if verifies successfully
int proofOfMultiplicationStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * A, EC_POINT * B, EC_POINT * C, EC_POINT * D, BIGNUM * s1, BIGNUM * s2, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * e, EC_POINT * com, BN_CTX * ctx){
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);

    int ret = 1;

    //Check if A^s1 = C^e * t1

    EC_POINT_mul(group, temp1, NULL, A, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, C, e, ctx);
    EC_POINT_add(group, temp2, temp2, t1, ctx);

    int cmp = EC_POINT_cmp(group, temp1, temp2, ctx);

    if( cmp != 0 ){
        ret = 0;
        printf("Failed cmp 1\n");
    }

    //Check if B^s1 = D^e * t2

    EC_POINT_mul(group, temp1, NULL, B, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, D, e, ctx);
    EC_POINT_add(group, temp2, temp2, t2, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp2, ctx);

    if( cmp != 0 ){
        ret = 0;
        printf("Failed cmp 2\n");
    }

    //Check if g_1^s2 * g^s1 = com^e * t3
    EC_POINT_mul(group, temp1, NULL, g1, s2, ctx);
    EC_POINT_mul(group, temp2, NULL, g, s1, ctx);
    EC_POINT_add(group, temp1, temp1, temp2, ctx);

    EC_POINT_mul(group, temp3, NULL, com, e, ctx);
    EC_POINT_add(group, temp3, temp3, t3, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp3, ctx);

    if( cmp != 0 ){
        ret = 0;
        printf("Failed cmp 3\n");
    }

    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);

    return ret;
}