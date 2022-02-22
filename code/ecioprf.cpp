#include <stdio.h>
#include "ecioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

//Creates size number of random BIGNUMs, each bits length long, and stores them in the vectors a and b
SENDERSTATE * initializeSender(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, int size, int bits) {
    SENDERSTATE * s = (SENDERSTATE *) malloc(sizeof(SENDERSTATE));

    s->group = group;
    s->ctx = BN_CTX_new();
    s->g1 = g1;
    s->g2 = g2;

    s->X0 = EC_POINT_new(group);
    s->X1 = EC_POINT_new(group);
    s->Y0 = EC_POINT_new(group);
    s->Y1 = EC_POINT_new(group);

    s->T0 = EC_POINT_new(group);
    s->T1 = EC_POINT_new(group);
    s->U0 = EC_POINT_new(group);
    s->U1 = EC_POINT_new(group);


    s->a = (BIGNUM**) calloc(size, sizeof(BIGNUM*));
    s->b = (BIGNUM**) calloc(size, sizeof(BIGNUM*));

    for(int x = 0; x < size; x++) {
        (s->a)[x] = BN_new();
        (s->b)[x] = BN_new();
        BN_rand((s->a)[x], bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_rand((s->b)[x], bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }

    return s;
}

//Initialize the receiver state
RECEIVERSTATE * initializeReceiver(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2) {
    //Malloc space for it
    RECEIVERSTATE * s = (RECEIVERSTATE *) malloc(sizeof(RECEIVERSTATE));

    s->randomize_r = (BIGNUM**) malloc(4*sizeof(BIGNUM*));
    s->randomize_back_r = (BIGNUM**) malloc(4*sizeof(BIGNUM*));

    for (int i = 0; i<4; i++) {
        s->randomize_r[i] = BN_new();
        s->randomize_back_r[i] = BN_new();
    }

    //Allocate all variables
    s->c0 = EC_POINT_new(group);
    s->cp0 = EC_POINT_new(group);
    s->d0 = EC_POINT_new(group);
    s->dp0 = EC_POINT_new(group);
    s->c1 = EC_POINT_new(group);
    s->cp1 = EC_POINT_new(group);
    s->d1 = EC_POINT_new(group);
    s->dp1 = EC_POINT_new(group);

    s->X0 = EC_POINT_new(group);
    s->X1 = EC_POINT_new(group);
    s->Y0 = EC_POINT_new(group);
    s->Y1 = EC_POINT_new(group);

    s->P0 = EC_POINT_new(group);
    s->Pp0 = EC_POINT_new(group);
    s->Q0 = EC_POINT_new(group);
    s->Qp0 = EC_POINT_new(group);
    s->P1 = EC_POINT_new(group);
    s->Pp1 = EC_POINT_new(group);
    s->Q1 = EC_POINT_new(group);
    s->Qp1 = EC_POINT_new(group);


    s->sk = BN_new();
    s->pk = EC_POINT_new(group);

    s->V0 = EC_POINT_new(group);
    s->D0 = EC_POINT_new(group);
    s->V1 = EC_POINT_new(group);
    s->D1 = EC_POINT_new(group);

    s->T0 = EC_POINT_new(group);
    s->T1 = EC_POINT_new(group);
    s->U0 = EC_POINT_new(group);
    s->U1 = EC_POINT_new(group);

    s->ctx = BN_CTX_new();

    s->g1 = g1;
    s->g2 = g2;
    s->group = group;

    //Generate encryption key with g1 as the generator
    generateECEGKey(group, s->g1, s->sk, s->pk, s->ctx);

    //Initialize V to E(1)
    s->one = BN_new();
    BN_one(s->one);
    s->r_enc_V = BN_new();
    encryptECEGwithR(group, s->g1, s->g2, s->pk, s->one, s->V1, s->V0, s->r_enc_V, s->ctx);

    //Initialize D to E(0)
    s->zero = BN_new();
    BN_zero(s->zero);
    s->r_enc_D = BN_new();
    encryptECEGwithR(group, s->g1, s->g2, s->pk, s->zero, s->D1, s->D0, s->r_enc_D, s->ctx);

    return s;
}

//Step 1 from the paper
//Receiver generates 4 random blinding values
//Calculates the shuffled c and d outputs
//Calculates T and U from those outputs
int receiverStep1(unsigned int x, RECEIVERSTATE * s) {

    BN_CTX * ctx = s->ctx;
    EC_POINT * g1 = s->g1;
    EC_GROUP * group = s->group;


    //Generate random blinding values
    randomBNFromECGroup(group, s->randomize_r[0], ctx);
    randomBNFromECGroup(group, s->randomize_r[1], ctx);
    randomBNFromECGroup(group, s->randomize_r[2], ctx);
    randomBNFromECGroup(group, s->randomize_r[3], ctx);

    //c
    EC_POINT_mul(group, s->c0, NULL, g1, s->randomize_r[0], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->c0, s->c0, s->V0, ctx);

    EC_POINT_mul(group, s->c1, NULL, s->pk, s->randomize_r[0], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->c1, s->c1, s->V1, ctx);

    //c'
    EC_POINT_mul(group, s->cp0, NULL, g1, s->randomize_r[1], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->cp0, s->cp0, s->V0, ctx);

    EC_POINT_mul(group, s->cp1, NULL, s->pk, s->randomize_r[1], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->cp1, s->cp1, s->V1, ctx);

    //d
    EC_POINT_mul(group, s->d0, NULL, g1, s->randomize_r[2], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->d0, s->d0, s->D0, ctx);

    EC_POINT_mul(group, s->d1, NULL, s->pk, s->randomize_r[2], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->d1, s->d1, s->D1, ctx);

    //d'
    EC_POINT_mul(group, s->dp0, NULL, g1, s->randomize_r[3], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->dp0, s->dp0, s->D0, ctx);

    EC_POINT_mul(group, s->dp1, NULL, s->pk, s->randomize_r[3], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->dp1, s->dp1, s->D1, ctx);

    //Calculate T and U
    EC_POINT_add(group, s->T0, s->c0, s->dp0, ctx);
    EC_POINT_add(group, s->T1, s->c1, s->dp1, ctx);

    EC_POINT_add(group, s->U0, s->cp0, s->d0, ctx);
    EC_POINT_add(group, s->U1, s->cp1, s->d1, ctx);

    return 0;
}

//Step 1c from the paper
int senderStep1c(SENDERSTATE *s, EC_POINT * c0, EC_POINT *c1, EC_POINT *cp0, EC_POINT *cp1, EC_POINT *d0, EC_POINT *d1, EC_POINT *dp0, EC_POINT *dp1) {

    EC_POINT_add(s->group, s->T0, c0, dp0, s->ctx);
    EC_POINT_add(s->group, s->T1, c1, dp1, s->ctx);

    EC_POINT_add(s->group, s->U0, cp0, d0, s->ctx);
    EC_POINT_add(s->group, s->U1, cp1, d1, s->ctx);
    return 0;
}

//Step 2 from the paper
//position is the index into the PRF key that should be used at this step
//Sender raises T to the alpha, outputs as X
//Sender raises U to the beta, ouputs as Y
int senderStep2(SENDERSTATE *s, int index, BIGNUM *r_renc_X, BIGNUM *r_renc_Y, EC_POINT *pk) {

    EC_POINT * T0 = s->T0;
    EC_POINT * T1 = s->T1;
    EC_POINT * U0 = s->U0;
    EC_POINT * U1 = s->U1;

    EC_GROUP * group = s->group;
    BN_CTX * ctx = s->ctx;

    EC_POINT * X0 = s->X0;
    EC_POINT * X1 = s->X1;
    EC_POINT * Y0 = s->Y0;
    EC_POINT * Y1 = s->Y1;

    BIGNUM  * alpha = (s->a)[index];
    BIGNUM  * beta = (s->b)[index];


    EC_POINT_mul(group, X0, NULL, T0, alpha, ctx);
    EC_POINT_mul(group, X1, NULL, T1, alpha, ctx);

    EC_POINT_mul(group, Y0, NULL, U0, beta, ctx);
    EC_POINT_mul(group, Y1, NULL, U1, beta, ctx);

    //Add reencryption
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    EC_POINT *tmp0 = EC_POINT_new(group);
    EC_POINT *tmp1 = EC_POINT_new(group);
    encryptECEGwithR(s->group, s->g1, s->g2, pk, zero, tmp1, tmp0, r_renc_X, ctx);
    EC_POINT_add(group, X0, X0, tmp0, ctx);
    EC_POINT_add(group, X1, X1, tmp1, ctx);

    encryptECEGwithR(s->group, s->g1, s->g2, pk, zero, tmp1, tmp0, r_renc_Y, ctx);
    EC_POINT_add(group, Y0, Y0, tmp0, ctx);
    EC_POINT_add(group, Y1, Y1, tmp1, ctx);

    EC_POINT_free(tmp0);
    EC_POINT_free(tmp1);
    BN_free(zero);
    return 0;
}

//Step 3 from the paper
//Receiver takes as input X and Y
//Unblinds and unshuffles to obtain new values of V and D
int receiverStep3(unsigned int x, RECEIVERSTATE * s) {

    BN_CTX * ctx = s->ctx;
    EC_GROUP * group = s->group;
    EC_POINT * g1 = s->g1;


    EC_POINT * X0 = s->X0;
    EC_POINT * X1 = s->X1;
    EC_POINT * Y0 = s->Y0;
    EC_POINT * Y1 = s->Y1;

    //P
    EC_POINT_mul(group, s->P0, NULL, g1, s->randomize_back_r[0], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->P0, s->P0, X0, ctx);

    EC_POINT_mul(group, s->P1, NULL, s->pk, s->randomize_back_r[0], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->P1, s->P1, X1, ctx);

    //P'
    EC_POINT_mul(group, s->Pp0, NULL, g1, s->randomize_back_r[1], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->Pp0, s->Pp0, X0, ctx);

    EC_POINT_mul(group, s->Pp1, NULL, s->pk, s->randomize_back_r[1], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->Pp1, s->Pp1, X1, ctx);

    //Q
    EC_POINT_mul(group, s->Q0, NULL, g1, s->randomize_back_r[2], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->Q0, s->Q0, Y0, ctx);

    EC_POINT_mul(group, s->Q1, NULL, s->pk, s->randomize_back_r[2], ctx);
    if( x == 1 )
        EC_POINT_add(group, s->Q1, s->Q1, Y1, ctx);

    //Q'
    EC_POINT_mul(group, s->Qp0, NULL, g1, s->randomize_back_r[3], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->Qp0, s->Qp0, Y0, ctx);

    EC_POINT_mul(group, s->Qp1, NULL, s->pk, s->randomize_back_r[3], ctx);
    if( x == 0 )
        EC_POINT_add(group, s->Qp1, s->Qp1, Y1, ctx);

    //Store results, update V and D
    EC_POINT_add(group, s->V0, s->P0, s->Qp0, ctx);
    EC_POINT_add(group, s->V1, s->P1, s->Qp1, ctx);

    EC_POINT_add(group, s->D0, s->Pp0, s->Q0, ctx);
    EC_POINT_add(group, s->D1, s->Pp1, s->Q1, ctx);


    return 0;
}

//Outputs iPRF evaluation at the receiver based on current value of V
unsigned char * receiverPRF(RECEIVERSTATE * s) {

    BN_CTX * ctx = s->ctx;
    EC_GROUP * group = s->group;

    EC_POINT * iprf = EC_POINT_new(group);

    //Reconstruct the shared key V[0]^sk
    EC_POINT_mul(group, iprf, NULL, s->V0, s->sk, ctx);

    //Calculate inverse
    EC_POINT_invert(group, iprf, ctx);

    //Multiply by V[1] to recover PRF value
    EC_POINT_add(group, iprf, iprf, s->V1, ctx);

    //Hash the BIGNUM to get PRF output as bytes
    unsigned char * ret = hashPoint(group, iprf, ctx);
    EC_POINT_free(iprf);
    return ret;
}

//Hashes a BIGNUM to a byte array using SHA256
unsigned char * hashPoint(EC_GROUP * group, EC_POINT * number, BN_CTX * ctx) {

    /*    int size = EC_POINT_point2oct(group, number, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
      unsigned char * numbytes = malloc(size);
      EC_POINT_point2oct(group, number, POINT_CONVERSION_UNCOMPRESSED, numbytes, size, ctx);*/
    unsigned char *numbytes;
    size_t size;
    point2BA(&numbytes, &size, number, group, ctx);

    unsigned char * finalbytes = (unsigned char *) malloc(32);

    unsigned int writtenbytes;
    EVP_Digest(numbytes, size, finalbytes, &writtenbytes, EVP_sha256(), NULL);

    return finalbytes;
}

//Sender's method for computing the PRF
//x is the PRF input, an array of integers, zeroes and ones
//length is the length of the input array x
unsigned char * senderPRF(SENDERSTATE * s, int * x, int length) {
    EC_GROUP * group = s->group;
    EC_POINT * g2 = s->g2;
    BN_CTX * ctx = s->ctx;

    //Calculate g2^\prod{b_i where x_i = 0} * \prod{a_i where x_i = 1}
    EC_POINT * iprf = EC_POINT_new(group);
    EC_POINT_copy(iprf, g2);
    for(int i = 0; i < length; i++) {
        if(x[i] == 1)
            EC_POINT_mul(group, iprf, NULL, iprf, s->a[i], ctx);
        else
            EC_POINT_mul(group, iprf, NULL, iprf, s->b[i], ctx);
    }
    return hashPoint(group, iprf, ctx);
}
