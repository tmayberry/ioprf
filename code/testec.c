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
    generateECParameters(&group, &ecg1, &ecg2, ctx);
      
}


int testOPRF(char * input){
    int iterations = strlen(input);

    int * x = malloc(sizeof(int) * iterations);

    for(int i = 0; i < iterations; i++){
        x[i] = input[i] == '1' ? 1 : 0;
    }

    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;

    if (readParameterFile(&group, &g1, &g2, ctx)==-1) {
      printf("Could not load parameter file.\n");
      return -1;
    }

    EC_POINT * X0, *X1, *Y0, *Y1;
    X0 = EC_POINT_new(group);
    X1 = EC_POINT_new(group);
    Y0 = EC_POINT_new(group);
    Y1 = EC_POINT_new(group);

    int runs = 100;
    printf("Testing PRF for input %s of length %d, %d runs\n", input, iterations,runs);

    clock_t start, end;
    double cpu_time_used = 0.0;

    
    for(int z = 0; z < runs; z++)
      {

        RECEIVERSTATE * rs = initializeReceiver(group, g1, g2, ctx);
        SENDERSTATE * ss = initializeSender(128, 128);

	start = clock();
        for( int y = 0; y < iterations; y++){
            receiverStep1(group, g1, x[y], rs, ctx);

            senderStep2(group, (ss->a)[y], (ss->b)[y], rs->T0, rs->T1, rs->U0, rs->U1, X0, X1, Y0, Y1, ctx);

            receiverStep3(group, g1, x[y], rs, X0, X1, Y0, Y1, ctx);

            //printf("Iteration %d: ", y+1);

	    //	    printf("iOPRF calculated by receiver:\n");

            unsigned char * recprf = receiverPRF(group, rs, ctx);
            //printBytes(recprf, 32);

            //printf("PRF calculated by sender:\n");

            unsigned char * sendprf = senderPRF(group, g2, ss, x, y+1, ctx);

	    end = clock();
	    cpu_time_used += (double) (end-start);
	    
            //printBytes(sendprf, 32);
	    if (memcmp(sendprf, recprf, 32)!=0) {
	      printf("FAIL\n");
	    } 
        }
    }
    printf("CPU time: %f ms per/IOPRF\n",1000.0*cpu_time_used/(CLOCKS_PER_SEC*runs));
    

    EC_POINT_free(g1);
    EC_POINT_free(g2);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    
    return 0;
}




int main(int argc, char ** argv){
  if(argc != 2){
        printf("No argument given, testing with default input string\n");
        //testOPRF("10101010");
        return testOPRF("10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010");
    }
    else if(strcmp(argv[1], "gen")==0){
        printf("Generating parameter file.\n");
        createParameterFile();
    }
    else{
        return testOPRF(argv[1]);
    }
    
}
