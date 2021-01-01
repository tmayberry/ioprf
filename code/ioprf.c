#include <stdio.h>
#include "ioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

int generateParameters(EC_GROUP *group, EC_POINT *g1, EC_POINT *g2, BN_CTX *ctx){
    int ok = 0;
    BIGNUM *k; 
    BIGNUM *order;

    k = BN_new();
    order = BN_new();

    //Get the order of the group
    if (!EC_GROUP_get_order(group, order, ctx)) goto err;

    //Choose a random number k (this can be 0 with negligible chance, won't worry about it)
    //Multiply generator by k to get a new random generator
    if (!BN_pseudo_rand(k, BN_num_bits(order), 0, 0)) goto err;
    if (!EC_POINT_mul(group,g1,k,NULL,NULL,ctx)) goto err;

    //Repeat again for second generator
    BN_print_fp(stdout, order);
    if (!BN_pseudo_rand(k, BN_num_bits(order), 0, 0)) goto err;
    if (!EC_POINT_mul(group,g2,k,NULL,NULL,ctx)) goto err;

    ok = 1;
err:
    if (k) 
        BN_free(k);
    if (order)
        BN_free(order);
    return ok; 
}

int main(){
    EC_GROUP *group;
    BN_CTX * ctx;
    EC_POINT * g2, *g1;

    group = EC_GROUP_new_by_curve_name(NID_secp224r1);

    ctx = BN_CTX_new();

    generateParameters(group, g1, g2, ctx);
        

    return 0;
}