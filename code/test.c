#include <stdio.h>
#include "ioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

void testElGamal(){
    BN_CTX * ctx;
    //Generate bignumber context, used for temporary storage by all the openssl functions
    ctx = BN_CTX_new();

    
    BIGNUM * egsk = BN_new();
    BIGNUM * egpk = BN_new();
    
    DHGROUP * group = chooseGroupParameters(ctx);

    generateEGKey(group->p, group->g1, egsk, egpk, ctx);

    unsigned int msgint = 20500;
    BIGNUM * msgbn = BN_new();
    BIGNUM * cbn = BN_new();
    BIGNUM * epkbn = BN_new();
    BIGNUM * msg2bn = BN_new();

    BN_lebin2bn((char*)(&msgint), 4, msgbn);

    printf("%s\n", BN_bn2dec(msgbn));

    encryptEG(group, egpk, msgbn, cbn, epkbn, ctx);
    decryptEG(group, egsk, epkbn, cbn, msg2bn, ctx);

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
      
}


void testOPRF(){
    BN_CTX * ctx = BN_CTX_new();
    DHGROUP * group = chooseGroupParameters(ctx);

    RECEIVERSTATE * rs = initializeReceiver(group, ctx);
    SENDERSTATE * ss = initializeSender(128, 2048);

    receiverStep1(group, 1, rs, ctx);

    BIGNUM * X0, *X1, *Y0, *Y1;
    X0 = BN_new();
    X1 = BN_new();
    Y0 = BN_new();
    Y1 = BN_new();

    senderStep2(group, (ss->a)[0], (ss->b)[0], rs->T0, rs->T1, rs->U0, rs->U1, X0, X1, Y0, Y1, ctx);

    receiverStep3(group, 1, rs, X0, X1, Y0, Y1, ctx);

    int x[] = {1};

    printf("iOPRF calculated by receiver:\n");

    unsigned char * recprf = receiverPRF(group, rs, ctx);

    for(int i = 0; i < 32; i++){
        printf("%x", recprf[i]);
    }
    printf("\n");

    printf("PRF calculated by sender:\n");

    unsigned char * sendprf = senderPRF(group, ss, x, 1, ctx);

    for(int i = 0; i < 32; i++){
        printf("%x", sendprf[i]);
    }
    printf("\n");
}


int main(){
    testOPRF();
}