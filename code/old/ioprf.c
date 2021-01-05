#include <stdio.h>
#include "ioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

//Choose group parameters, including p, g1 and g2
DHGROUP * chooseGroupParameters(BN_CTX * ctx){
    DHGROUP * group = malloc(sizeof(DHGROUP));
    group->p = BN_get_rfc3526_prime_2048(NULL);
    group->g1 = BN_new();
    group->g2 = BN_new();

    randomBNFromPrimeGroup(group->p, group->g1, ctx);
    randomBNFromPrimeGroup(group->p, group->g2, ctx);

    return group;
}

//Creates size number of random BIGNUMs, each bits length long, and stores them in the vectors a and b
SENDERSTATE * initializeSender(int size, int bits){
    SENDERSTATE * s = malloc(sizeof(SENDERSTATE));

    s->a = calloc(size, sizeof(BIGNUM*));
    s->b = calloc(size, sizeof(BIGNUM*));

    for(int x = 0; x < size; x++){
        (s->a)[x] = BN_new();
        (s->b)[x] = BN_new();
        BN_rand((s->a)[x], bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_rand((s->b)[x], bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }
    
    return s;
}

//Initialize the receiver state 
RECEIVERSTATE * initializeReceiver(DHGROUP * group, BN_CTX * ctx){
    //Malloc space for it
    RECEIVERSTATE * s = malloc(sizeof(RECEIVERSTATE));

    //Allocated all BIGNUMs
    s->sk = BN_new();
    s->pk = BN_new();

    s->V0 = BN_new(); 
    s->D0 = BN_new(); 
    s->V1 = BN_new(); 
    s->D1 = BN_new();

    s->T0 = BN_new(); 
    s->T1 = BN_new(); 
    s->U0 = BN_new(); 
    s->U1 = BN_new(); 

    s->ctx = BN_CTX_new();

    //Generate encryption key with g1 as the generator
    generateEGKey(group->p, group->g1, s->sk, s->pk, ctx);

    //Initialize V to E(1)
    encryptIntEG(group, s->pk, 1, s->V1, s->V0, ctx);

    //Initialize D to E(0)
    encryptIntEG(group, s->pk, 0, s->D1, s->D0, ctx);

    return s;
}

//Step 1 from the paper
//Receiver generates 4 random blinding values
//Calculates the shuffled c and d outputs
//Calculates T and U from those outputs
int receiverStep1(DHGROUP * group, unsigned int x, RECEIVERSTATE * s, BN_CTX * ctx){

    BIGNUM * r0, * r1, * r2, * r3;

    r0 = BN_new();
    r1 = BN_new();
    r2 = BN_new();
    r3 = BN_new();

    //Generate random blinding values
    BN_rand_range(r0, group->p);
    BN_rand_range(r1, group->p);
    BN_rand_range(r2, group->p);
    BN_rand_range(r3, group->p);

    //Intermediate values c, c', d and d'
    BIGNUM *c0, *c1, *cp0, *cp1, *d0, *d1, *dp0, *dp1;
    c0 = BN_new();
    cp0 = BN_new();
    d0 = BN_new();
    dp0 = BN_new();
    c1 = BN_new();
    cp1 = BN_new();
    d1 = BN_new();
    dp1 = BN_new();

    //c
    BN_mod_exp(c0, group->g1, r0, group->p, ctx);
    if( x == 1 )
        BN_mod_mul(c0, c0, s->V0, group->p, ctx);

    BN_mod_exp(c1, s->pk, r0, group->p, ctx);
    if( x == 1)
        BN_mod_mul(c1, c1, s->V1, group->p, ctx);
    
    //c'
    BN_mod_exp(cp0, group->g1, r1, group->p, ctx);
    if( x == 0 )
        BN_mod_mul(cp0, cp0, s->V0, group->p, ctx);

    BN_mod_exp(cp1, s->pk, r1, group->p, ctx);
    if( x == 0)
        BN_mod_mul(cp1, cp1, s->V1, group->p, ctx);

    //d
    BN_mod_exp(d0, group->g1, r2, group->p, ctx);
    if( x == 1 )
        BN_mod_mul(d0, d0, s->D0, group->p, ctx);

    BN_mod_exp(d1, s->pk, r2, group->p, ctx);
    if( x == 1)
        BN_mod_mul(d1, d1, s->D1, group->p, ctx);

    //d'
    BN_mod_exp(dp0, group->g1, r3, group->p, ctx);
    if( x == 0 )
        BN_mod_mul(dp0, dp0, s->D0, group->p, ctx);

    BN_mod_exp(dp1, s->pk, r3, group->p, ctx);
    if( x == 0)
        BN_mod_mul(dp1, dp1, s->D1, group->p, ctx);

    //Calculate T and U
    BN_mod_mul(s->T0, c0, dp0, group->p, ctx);
    BN_mod_mul(s->T1, c1, dp1, group->p, ctx);

    BN_mod_mul(s->U0, cp0, d0, group->p, ctx);
    BN_mod_mul(s->U1, cp1, d1, group->p, ctx);


    BN_free(c0);
    BN_free(c1);
    BN_free(cp0);
    BN_free(cp1);
    BN_free(d0);
    BN_free(d1);
    BN_free(dp0);
    BN_free(dp1);
    BN_free(r0);
    BN_free(r1);
    BN_free(r2);
    BN_free(r3);

    return 0;
}

//Step 2 from the paper
//position is the index into the PRF key that should be used at this step
//Sender raises T to the alpha, outputs as X
//Sender raises U to the beta, ouputs as Y
int senderStep2(DHGROUP * group, BIGNUM * alpha, BIGNUM * beta, BIGNUM * T0, BIGNUM * T1, BIGNUM * U0, BIGNUM * U1, BIGNUM * X0, BIGNUM * X1, BIGNUM * Y0, BIGNUM * Y1, BN_CTX * ctx){
    BN_mod_exp(X0, T0, alpha, group->p, ctx);
    BN_mod_exp(X1, T1, alpha, group->p, ctx);
    BN_mod_exp(Y0, U0, beta, group->p, ctx);
    BN_mod_exp(Y1, U1, beta, group->p, ctx);

    return 0;
}

//Step 3 from the paper
//Receiver takes as input X and Y
//Unblinds and unshuffles to obtain new values of V and D
int receiverStep3(DHGROUP * group, unsigned int x, RECEIVERSTATE * s, BIGNUM * X0, BIGNUM * X1, BIGNUM * Y0, BIGNUM * Y1, BN_CTX * ctx){
    BIGNUM *P0, *P1, *Pp0, *Pp1, *Q0, *Q1, *Qp0, *Qp1;
    P0 = BN_new();
    Pp0 = BN_new();
    Q0 = BN_new();
    Qp0 = BN_new();
    P1 = BN_new();
    Pp1 = BN_new();
    Q1 = BN_new();
    Qp1 = BN_new();

    BIGNUM * r0, * r1, * r2, * r3;

    r0 = BN_new();
    r1 = BN_new();
    r2 = BN_new();
    r3 = BN_new();

    //P
    BN_mod_exp(P0, group->g1, r0, group->p, ctx);
    if( x == 1 )
        BN_mod_mul(P0, P0, X0, group->p, ctx);

    BN_mod_exp(P1, s->pk, r0, group->p, ctx);
    if( x == 1)
        BN_mod_mul(P1, P1, X1, group->p, ctx);
    
    //P'
    BN_mod_exp(Pp0, group->g1, r1, group->p, ctx);
    if( x == 0 )
        BN_mod_mul(Pp0, Pp0, X0, group->p, ctx);

    BN_mod_exp(Pp1, s->pk, r1, group->p, ctx);
    if( x == 0)
        BN_mod_mul(Pp1, Pp1, X1, group->p, ctx);

    //Q
    BN_mod_exp(Q0, group->g1, r2, group->p, ctx);
    if( x == 1 )
        BN_mod_mul(Q0, Q0, Y0, group->p, ctx);

    BN_mod_exp(Q1, s->pk, r2, group->p, ctx);
    if( x == 1)
        BN_mod_mul(Q1, Q1, Y1, group->p, ctx);

    //Q'
    BN_mod_exp(Qp0, group->g1, r3, group->p, ctx);
    if( x == 0 )
        BN_mod_mul(Qp0, Qp0, Y0, group->p, ctx);

    BN_mod_exp(Qp1, s->pk, r3, group->p, ctx);
    if( x == 0)
        BN_mod_mul(Qp1, Qp1, Y1, group->p, ctx);

    //Store results
    BN_mod_mul(s->V0, P0, Qp0, group->p, ctx);
    BN_mod_mul(s->V1, P1, Qp1, group->p, ctx);

    BN_mod_mul(s->D0, Pp0, Q0, group->p, ctx);
    BN_mod_mul(s->D1, Pp1, Q1, group->p, ctx);

    BN_free(P0);
    BN_free(Pp0);
    BN_free(Q0);
    BN_free(Qp0);
    BN_free(P1);
    BN_free(Pp1);
    BN_free(Q1);
    BN_free(Qp1);

    BN_free(r0);
    BN_free(r1);
    BN_free(r2);
    BN_free(r3);

    return 0;
}

//Outputs iPRF evaluation at the receiver based on current value of V
unsigned char * receiverPRF(DHGROUP * group, RECEIVERSTATE * s, BN_CTX * ctx){
    BIGNUM * iprf = BN_new();

    //Reconstruct the shared key V[0]^sk
    BN_mod_exp(iprf, s->V0, s->sk, group->p, ctx);
    //Calculate inverse
    BN_mod_inverse(iprf,iprf, group->p, ctx);
    //Multiply by V[1] to recover PRF value
    BN_mod_mul(iprf, iprf, s->V1, group->p, ctx);

    //Hash the BIGNUM to get PRF output as bytes
    unsigned char * ret = hashBN(iprf);
    BN_free(iprf);
    return ret;
}

//Hases a BIGNUM to a byte array using SHA256
unsigned char * hashBN(BIGNUM * number){
    int size = BN_num_bytes(number);
    unsigned char * numbytes = malloc(size);
    unsigned char * finalbytes = malloc(32);

    BN_bn2bin(number, numbytes);

    int writtenbytes;
    EVP_Digest(numbytes, size, finalbytes, &writtenbytes, EVP_sha256(), NULL);

    return finalbytes;
}

//Sender's method for computing the PRF
//x is the PRF input, an array of integers, zeroes and ones
//length is the length of the input array x
unsigned char * senderPRF(DHGROUP * group, SENDERSTATE * s, int * x, int length, BN_CTX * ctx){
    //Calculate g2^\prod{b_i where x_i = 0} * \prod{a_i where x_i = 1}
    BIGNUM * iprf = BN_new();
    BN_copy(iprf, group->g2);
    for(int i = 0; i < length; i++){
        if(x[i] == 1)
            BN_mod_exp(iprf, iprf, s->a[i], group->p, ctx);
        else
            BN_mod_exp(iprf, iprf, s->b[i], group->p, ctx);
    }
    return hashBN(iprf);
}
