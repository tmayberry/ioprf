#include <stdio.h>
#include "ecioprf.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <string.h>

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


void testOPRF(char * input){
    int iterations = strlen(input);

    int * x = malloc(sizeof(int) * iterations);

    for(int i = 0; i < iterations; i++){
        x[i] = input[i] == '1' ? 1 : 0;
    }

    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group = EC_GROUP_new_by_curve_name(NID_secp224r1);

    EC_POINT * g1 = EC_POINT_new(group);
    EC_POINT * g2 = EC_POINT_new(group);

    generateECParameters(group, g1, g2, ctx);

    RECEIVERSTATE * rs = initializeReceiver(group, g1, g2, ctx);
    SENDERSTATE * ss = initializeSender(128, 2048);

    printf("Testing PRF for input %s of length %d\n\n", input, iterations);

    EC_POINT * X0, *X1, *Y0, *Y1;
    X0 = EC_POINT_new(group);
    X1 = EC_POINT_new(group);
    Y0 = EC_POINT_new(group);
    Y1 = EC_POINT_new(group);

    for( int y = 0; y < iterations; y++){
        receiverStep1(group, g1, x[y], rs, ctx);

        senderStep2(group, (ss->a)[y], (ss->b)[y], rs->T0, rs->T1, rs->U0, rs->U1, X0, X1, Y0, Y1, ctx);

        receiverStep3(group, g1, x[y], rs, X0, X1, Y0, Y1, ctx);

        printf("\nIteration %d ---------\n\n", y+1);

        printf("iOPRF calculated by receiver:\n");

        unsigned char * recprf = receiverPRF(group, rs, ctx);
        printBytes(recprf, 32);

        printf("PRF calculated by sender:\n");

        unsigned char * sendprf = senderPRF(group, g2, ss, x, y+1, ctx);
        printBytes(sendprf, 32);
    }
}


int main(int argc, char ** argv){
    if(argc != 2){
        printf("No argument given, testing with default input string\n");
        testOPRF("1010101");
    }
    else
        testOPRF(argv[1]);
}