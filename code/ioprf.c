#include <stdio.h>
#include "ioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

//Generate a random BIGNUM from the numbers [1,N-1] where N is the size of the group
int randomBNFromECGroup(EC_GROUP * group, BIGNUM * output, BN_CTX * ctx){
    BIGNUM *order;
    order = BN_new();

     //Get the order of the group
    EC_GROUP_get_order(group, order, ctx);

    BN_priv_rand_range(output, order);

    BN_free(order);

    return 0;
}

//Creates the two generators g1 and g2 for an elliptic curve
//g1 and g2 must be initialized EC_POINT objects
int generateECParameters(EC_GROUP *group, EC_POINT *g1, EC_POINT *g2, BN_CTX *ctx){
    int ok = 0;
    BIGNUM *k; 
    

    k = BN_new();
    
    //Choose a random number k (this can be 0 with negligible chance, we won't worry about it)
    //Multiply generator by k to get a new random generator
    //g1 could be 1 or -1 but only with negligible chance so again we won't worry about it
    randomBNFromECGroup(group, k, ctx);
    EC_POINT_mul(group,g1,k,NULL,NULL,ctx);

    //Repeat again for second generator
    randomBNFromECGroup(group, k, ctx);
    EC_POINT_mul(group,g2,k,NULL,NULL,ctx);

    BN_free(k);

    return 0;
}

//Creates size number of random BIGNUMs, each bits length long, and stores them in p
int generatePRFKey(BIGNUM ** p, int size, int bits){
    for(int x = 0; x < size; x++){
        BN_rand(p[x], bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }
    return 0;
}

//Generates a random public/secret keypair on the specified curve with the specified generator
int generateECEGKey(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * pk,  BN_CTX * ctx){
    //Generate random number in Z_p, store as sk
    randomBNFromECGroup(group, sk, ctx);
    //Generate public key = sk * g
    EC_POINT_mul(group,NULL,NULL,g,sk,ctx);

    return 0;
}

//Encrypt msg with public key pk, using generator g, store ciphertext as c and the ephemeral public key as epk
int encryptECEG(EC_GROUP * group, EC_POINT * g, EC_POINT * pk, BIGNUM * msg, EC_POINT * c, EC_POINT * epk, BN_CTX * ctx)
{
    BIGNUM * k = BN_new();

    //Convert msg to an EC point
    EC_POINT * msgpoint = EC_POINT_new(group);
    EC_POINT_bn2point(group, msg, msgpoint, ctx);

    //Generate ephemeral public key
    randomBNFromECGroup(group, k, ctx);
    EC_POINT_mul(group, epk, NULL, g, k, ctx);

    //Generate ciphertext
    EC_POINT_mul(group, c, NULL, pk, k, ctx);
    EC_POINT_add(group, c, c, msgpoint, ctx);

    BN_free(k);
    EC_POINT_free(msgpoint);

    return 0;
}

int decryptECEG(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * epk, EC_POINT * c, BIGNUM * m, BN_CTX * ctx){
    //Recover shared key
    EC_POINT * sharedKey = EC_POINT_new(group);
    EC_POINT_mul(group, sharedKey, NULL, epk, sk, ctx);

    //Decrypt point
    EC_POINT * msgpoint = EC_POINT_new(group);
    EC_POINT_invert(group, sharedKey, ctx);
    EC_POINT_add(group, msgpoint, c, sharedKey, ctx);

    //Recover BIGNUM message
    EC_POINT_point2bn(group, g, POINT_CONVERSION_UNCOMPRESSED, m, ctx);

    EC_POINT_free(sharedKey);
    EC_POINT_free(msgpoint);

    return 0;
}

//Get two random generators of QR_p
int generateParameters(BIGNUM * p, BIGNUM * g1, BIGNUM * g2, BN_CTX * ctx){
    BN_rand_range(g1, p);
    BN_rand_range(g2, p);
    
    BN_mod_sqr(g1, g1, p, ctx);
    BN_mod_sqr(g2, g2, p, ctx);

    return 0;
}

//Generate ElGamal public and secret keys for group with generator g
int generateEGKey(BIGNUM * p, BIGNUM * g, BIGNUM * sk, BIGNUM * pk, BN_CTX * ctx){
    BN_rand_range(sk, p);
    BN_mod_exp(pk, g, sk, p, ctx);

    return 0;
}

int encryptEG(BIGNUM * p, BIGNUM * g, BIGNUM * pk, BIGNUM * m, BIGNUM * c, BIGNUM * epk, BN_CTX * ctx){
    BIGNUM * k = BN_new();
    BN_rand_range(k, p);

    BN_mod_exp(epk, g, k, p, ctx);
    BN_mod_exp(c, pk, k, p, ctx);
    BN_mod_mul(c, c, m, p, ctx);

    BN_free(k);

    return 0;
}

int decryptEG(BIGNUM * p, BIGNUM * g, BIGNUM * sk, BIGNUM * epk, BIGNUM * c, BIGNUM * m, BN_CTX * ctx){
    BIGNUM * sharedkey = BN_new();
    BN_mod_exp(sharedkey, epk, sk, p, ctx);
    BN_mod_inverse(sharedkey, sharedkey, p, ctx);
    BN_mod_mul(m, sharedkey, c, p, ctx);

    return 0;
}


int main(){
    int keysize = 128; //Number of elements in the private key
    int bitlength = 128; //Size of elements in the private key

    EC_GROUP *group;
    BN_CTX * ctx;
    EC_POINT * ecg2, *ecg1;

    //Allocate and initialize bignums for the private key
    BIGNUM ** privkey = calloc(sizeof(BIGNUM *),keysize);
    for(int x = 0; x < keysize; x++){
        privkey[x] = BN_new();
    }

    //Get EC group
    group = EC_GROUP_new_by_curve_name(NID_secp224r1);

    //Generate bignumber context, used for temporary storage by all the openssl functions
    ctx = BN_CTX_new();

    //Get two random generators of the group
    generateECParameters(group, ecg1, ecg2, ctx);
    
    //Generate random elements for the private key
    generatePRFKey(privkey, keysize, bitlength);


    return 0;
}