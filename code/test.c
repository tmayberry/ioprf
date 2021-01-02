#include <stdio.h>
#include "ioprf.h"
#include "util.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

void testElGamal(){
    BN_CTX * ctx;
    //Generate bignumber context, used for temporary storage by all the openssl functions
    ctx = BN_CTX_new();

    
    BIGNUM * egsk = BN_new();
    BIGNUM * egpk = BN_new();
    BIGNUM * p = BN_get_rfc3526_prime_2048(NULL);
    BIGNUM * g = BN_new();
    randomBNFromPrimeGroup(p, g, ctx);

    generateEGKey(p, g, egsk, egpk, ctx);

    unsigned int msgint = 20500;
    BIGNUM * msgbn = BN_new();
    BIGNUM * cbn = BN_new();
    BIGNUM * epkbn = BN_new();
    BIGNUM * msg2bn = BN_new();

    BN_lebin2bn((char*)(&msgint), 4, msgbn);

    printf("%s\n", BN_bn2dec(msgbn));

    encryptEG(p, g, egpk, msgbn, cbn, epkbn, ctx);
    decryptEG(p, g, egsk, epkbn, cbn, msg2bn, ctx);

    printf("%s\n", BN_bn2dec(msg2bn));
}

void testECElGamal(){
    BN_CTX * ctx;
    //Generate bignumber context, used for temporary storage by all the openssl functions
    ctx = BN_CTX_new();

    int keysize = 128; //Number of elements in the private key
    int bitlength = 128; //Size of elements in the private key

    EC_GROUP *group;

    EC_POINT * ecg2, *ecg1;

    //Allocate and initialize bignums for the private key
    BIGNUM ** privkey = calloc(sizeof(BIGNUM *),keysize);
    for(int x = 0; x < keysize; x++){
        privkey[x] = BN_new();
    }

    //Get EC group
    group = EC_GROUP_new_by_curve_name(NID_secp224r1);

    //Get two random generators of the group
    generateECParameters(group, ecg1, ecg2, ctx);
    
    //Generate random elements for the private key
    generatePRFKey(privkey, keysize, bitlength);    
}


int main(){
    testElGamal();
}