#include <stdio.h>
#include "ecioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

//Creates size number of random BIGNUMs, each bits length long, and stores them in the vectors a and b
SENDERSTATE * initializeSender(EC_GROUP * group, EC_POINT * g2, int size, int bits){
    SENDERSTATE * s = malloc(sizeof(SENDERSTATE));

    s->group = group;
    s->ctx = BN_CTX_new();
    s->g2 = g2;
    
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
RECEIVERSTATE * initializeReceiver(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2){
    //Malloc space for it
    RECEIVERSTATE * s = malloc(sizeof(RECEIVERSTATE));

    //Allocate all variables
    s->c0 = EC_POINT_new(group);
    s->cp0 = EC_POINT_new(group);
    s->d0 = EC_POINT_new(group);
    s->dp0 = EC_POINT_new(group);
    s->c1 = EC_POINT_new(group);
    s->cp1 = EC_POINT_new(group);
    s->d1 = EC_POINT_new(group);
    s->dp1 = EC_POINT_new(group);
    
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
    BIGNUM * one = BN_new();
    BN_one(one);
    encryptECEG(group, s->g1, s->g2, s->pk, one, s->V1, s->V0, s->ctx);
    BN_free(one);

    //Initialize D to E(0)
    BIGNUM * zero = BN_new();
    BN_zero(zero);
    encryptECEG(group, s->g1, s->g2, s->pk, zero, s->D1, s->D0, s->ctx);
    BN_free(zero);

    return s;
}

//Step 1 from the paper
//Receiver generates 4 random blinding values
//Calculates the shuffled c and d outputs
//Calculates T and U from those outputs
int receiverStep1(unsigned int x, RECEIVERSTATE * s){

  BN_CTX * ctx = s->ctx;
  EC_POINT * g1 = s->g1;
  EC_GROUP * group = s->group;
  
   BIGNUM * r0, * r1, * r2, * r3;

    r0 = BN_new();
    r1 = BN_new();
    r2 = BN_new();
    r3 = BN_new();

    //Generate random blinding values
    randomBNFromECGroup(group, r0, ctx);
    randomBNFromECGroup(group, r1, ctx);
    randomBNFromECGroup(group, r2, ctx);
    randomBNFromECGroup(group, r3, ctx);


    //Intermediate values c, c', d and d'
    /*    
    EC_POINT *c0, *c1, *cp0, *cp1, *d0, *d1, *dp0, *dp1;
    c0 = EC_POINT_new(group);
    cp0 = EC_POINT_new(group);
    d0 = EC_POINT_new(group);
    dp0 = EC_POINT_new(group);
    c1 = EC_POINT_new(group);
    cp1 = EC_POINT_new(group);
    d1 = EC_POINT_new(group);
    dp1 = EC_POINT_new(group);
    */

    //c
    EC_POINT_mul(group, s->c0, NULL, g1, r0, ctx);
    if( x == 1 )
        EC_POINT_add(group, s->c0, s->c0, s->V0, ctx);

    EC_POINT_mul(group, s->c1, NULL, s->pk, r0, ctx);
    if( x == 1 )
        EC_POINT_add(group, s->c1, s->c1, s->V1, ctx);
    
    //c'
    EC_POINT_mul(group, s->cp0, NULL, g1, r1, ctx);
    if( x == 0 )
        EC_POINT_add(group, s->cp0, s->cp0, s->V0, ctx);

    EC_POINT_mul(group, s->cp1, NULL, s->pk, r1, ctx);
    if( x == 0 )
        EC_POINT_add(group, s->cp1, s->cp1, s->V1, ctx);

    //d
    EC_POINT_mul(group, s->d0, NULL, g1, r2, ctx);
    if( x == 1 )
        EC_POINT_add(group, s->d0, s->d0, s->D0, ctx);

    EC_POINT_mul(group, s->d1, NULL, s->pk, r2, ctx);
    if( x == 1 )
        EC_POINT_add(group, s->d1, s->d1, s->D1, ctx);

    //d'
    EC_POINT_mul(group, s->dp0, NULL, g1, r3, ctx);
    if( x == 0 )
        EC_POINT_add(group, s->dp0, s->dp0, s->D0, ctx);

    EC_POINT_mul(group, s->dp1, NULL, s->pk, r3, ctx);
    if( x == 0 )
        EC_POINT_add(group, s->dp1, s->dp1, s->D1, ctx);

    //Calculate T and U
    EC_POINT_add(group, s->T0, s->c0, s->dp0, ctx);
    EC_POINT_add(group, s->T1, s->c1, s->dp1, ctx);

    EC_POINT_add(group, s->U0, s->cp0, s->d0, ctx);
    EC_POINT_add(group, s->U1, s->cp1, s->d1, ctx);

    /*    EC_POINT_free(c0);
    EC_POINT_free(c1);
    EC_POINT_free(cp0);
    EC_POINT_free(cp1);
    EC_POINT_free(d0);
    EC_POINT_free(d1);
    EC_POINT_free(dp0);
    EC_POINT_free(dp1);
    */
    
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
int senderStep2(SENDERSTATE *s, int index, EC_POINT * T0, EC_POINT * T1, EC_POINT * U0, EC_POINT * U1, EC_POINT * X0, EC_POINT * X1, EC_POINT * Y0, EC_POINT * Y1){
  EC_GROUP * group = s->group;
   BN_CTX * ctx = s->ctx;

   BIGNUM  * alpha = (s->a)[index];
   BIGNUM  * beta = (s->b)[index];

   
    EC_POINT_mul(group, X0, NULL, T0, alpha, ctx);
    EC_POINT_mul(group, X1, NULL, T1, alpha, ctx);
    EC_POINT_mul(group, Y0, NULL, U0, beta, ctx);
    EC_POINT_mul(group, Y1, NULL, U1, beta, ctx);

    return 0;
}

//Step 3 from the paper
//Receiver takes as input X and Y
//Unblinds and unshuffles to obtain new values of V and D
int receiverStep3(unsigned int x, RECEIVERSTATE * s, EC_POINT * X0, EC_POINT * X1, EC_POINT * Y0, EC_POINT * Y1){

  BN_CTX * ctx = s->ctx;
  EC_GROUP * group = s->group;
  EC_POINT * g1 = s->g1;
  
    EC_POINT *P0, *P1, *Pp0, *Pp1, *Q0, *Q1, *Qp0, *Qp1;
    P0 = EC_POINT_new(group);
    Pp0 = EC_POINT_new(group);
    Q0 = EC_POINT_new(group);
    Qp0 = EC_POINT_new(group);
    P1 = EC_POINT_new(group);
    Pp1 = EC_POINT_new(group);
    Q1 = EC_POINT_new(group);
    Qp1 = EC_POINT_new(group);

    BIGNUM * r0, * r1, * r2, * r3;

    r0 = BN_new();
    r1 = BN_new();
    r2 = BN_new();
    r3 = BN_new();

    //P
    EC_POINT_mul(group, P0, NULL, g1, r0, ctx);
    if( x == 1 )
        EC_POINT_add(group, P0, P0, X0, ctx);

    EC_POINT_mul(group, P1, NULL, s->pk, r0, ctx);
    if( x == 1 )
        EC_POINT_add(group, P1, P1, X1, ctx);
    
    //P'
    EC_POINT_mul(group, Pp0, NULL, g1, r1, ctx);
    if( x == 0 )
        EC_POINT_add(group, Pp0, Pp0, X0, ctx);

    EC_POINT_mul(group, Pp1, NULL, s->pk, r1, ctx);
    if( x == 0 )
        EC_POINT_add(group, Pp1, Pp1, X1, ctx);

    //Q
    EC_POINT_mul(group, Q0, NULL, g1, r2, ctx);
    if( x == 1 )
        EC_POINT_add(group, Q0, Q0, Y0, ctx);

    EC_POINT_mul(group, Q1, NULL, s->pk, r2, ctx);
    if( x == 1 )
        EC_POINT_add(group, Q1, Q1, Y1, ctx);

    //Q'
    EC_POINT_mul(group, Qp0, NULL, g1, r3, ctx);
    if( x == 0 )
        EC_POINT_add(group, Qp0, Qp0, Y0, ctx);

    EC_POINT_mul(group, Qp1, NULL, s->pk, r3, ctx);
    if( x == 0 )
        EC_POINT_add(group, Qp1, Qp1, Y1, ctx);

    //Store results
    EC_POINT_add(group, s->V0, P0, Qp0, ctx);
    EC_POINT_add(group, s->V1, P1, Qp1, ctx);

    EC_POINT_add(group, s->D0, Pp0, Q0, ctx);
    EC_POINT_add(group, s->D1, Pp1, Q1, ctx);

    EC_POINT_free(P0);
    EC_POINT_free(Pp0);
    EC_POINT_free(Q0);
    EC_POINT_free(Qp0);
    EC_POINT_free(P1);
    EC_POINT_free(Pp1);
    EC_POINT_free(Q1);
    EC_POINT_free(Qp1);

    BN_free(r0);
    BN_free(r1);
    BN_free(r2);
    BN_free(r3);

    return 0;
}

//Outputs iPRF evaluation at the receiver based on current value of V
unsigned char * receiverPRF(RECEIVERSTATE * s){
  
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
unsigned char * hashPoint(EC_GROUP * group, EC_POINT * number, BN_CTX * ctx){

    int size = EC_POINT_point2oct(group, number, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    unsigned char * numbytes = malloc(size);
    EC_POINT_point2oct(group, number, POINT_CONVERSION_UNCOMPRESSED, numbytes, size, ctx);
    unsigned char * finalbytes = malloc(32);

    unsigned int writtenbytes;
    EVP_Digest(numbytes, size, finalbytes, &writtenbytes, EVP_sha256(), NULL);

    return finalbytes;
}

//Sender's method for computing the PRF
//x is the PRF input, an array of integers, zeroes and ones
//length is the length of the input array x
unsigned char * senderPRF(SENDERSTATE * s, int * x, int length){
  EC_GROUP * group = s->group;
  EC_POINT * g2 = s->g2;
  BN_CTX * ctx = s->ctx;
 
  //Calculate g2^\prod{b_i where x_i = 0} * \prod{a_i where x_i = 1}
    EC_POINT * iprf = EC_POINT_new(group);
    EC_POINT_copy(iprf, g2);
    for(int i = 0; i < length; i++){
        if(x[i] == 1)
            EC_POINT_mul(group, iprf, NULL, iprf, s->a[i], ctx);
        else
            EC_POINT_mul(group, iprf, NULL, iprf, s->b[i], ctx);
    }
    return hashPoint(group, iprf, ctx);
}
