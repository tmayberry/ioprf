#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <omp.h>


#include "psi-lib.h"
#include "net.h"


int main(int argc, char **argv)
{
      if (argc<3) {
        printf("Need n as 1st parameter, and client file name as second.\n");
        exit(1);
    }

    unsigned long n = strtoul(argv[1], NULL, 10);
    printf("n = %ld\n",n);

    FILE *f = fopen(argv[2], "r");
    if (f == NULL) {
      printf("Cannot open file\n");
      exit(1);
    }


    EC_GROUP *group;
    if(NULL == (group = EC_GROUP_new_by_curve_name(NID_secp224r1)))
        handleErrors(4);

    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP_precompute_mult(group, ctx);

    BIGNUM *order = BN_new();
    if (1!=EC_GROUP_get_order(group, order, ctx)) {
        printf("Cannot get curve order\n");
        exit(1);
    }


    BIGNUM **clientSet = initBN(n);
    BIGNUM **clientSetMasked = initBN(n);

    BIGNUM *clientSecret = BN_new();
    fillRandom(&clientSecret, order, 1);

    BIGNUM *inv = BN_new();
    if (NULL==BN_mod_inverse(inv, clientSecret, order, ctx)) {
        printf("Secret does not have an inverse\n");
        exit(1);
    }

    printf("Done with init\n");
    fillRandom(clientSet, order, n);
    char **inputStrings = malloc(n * sizeof(char *));
    fetchFile(inputStrings, clientSet, f, NULL, n, CLIENT, order, ctx);
    fclose(f);
    printf("Done reading file\n");

    printf("Done with choosing random elements\n");

    mulBN(clientSetMasked, clientSet, clientSecret, order, n);
    printf("Done with prime sets\n");

    EC_POINT **clientOPRFInput = initECPoints(n, group);
    EC_POINT **serverOPRFOutput = initECPoints(n, group);
    EC_POINT **clientOPRFOutput = initECPoints(n, group);
    EC_POINT **maskedServerOPRFOutput = initECPoints(n, group);
    EC_POINT **serverKeyedPoints = initECPoints(n, group);

    //do random point multiply
    double ttime = 0.0;
    double start = omp_get_wtime();
    mulPointsGenerator(group, clientOPRFInput, clientSetMasked, n);
    double end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with client set multiplication in: %f s\n\nConnecting and sending...", end-start);

    //Connect
    int sockfd;
    myClient(&sockfd);

    //Exchange
    start = omp_get_wtime();
    printf("Sending my points...\n");
    sendPoints(sockfd, clientOPRFInput, n, group, ctx);

    printf("Receiving server serverOPRFOutput...\n");
    receivePoints(sockfd, serverOPRFOutput, n, group);

    printf("Receiving my points back...\n");
    receivePoints(sockfd, clientOPRFOutput, n, group);

    printf("Receiving server keyed points back...\n");
    receivePoints(sockfd, serverKeyedPoints, n, group);

    printf("Receiving ciphertexts...\n");
    unsigned char *ciphertexts = malloc(n*CIPHERTEXT_LENGTH);
    receiveData(sockfd, ciphertexts, n*CIPHERTEXT_LENGTH);

    /*    for (int i = 0;i<n;i++) {
      for (int j = 0;j<CIPHERTEXT_LENGTH;j++) {
    printf("%02x", (ciphertexts[i*CIPHERTEXT_LENGTH+j]));
      }
      printf("\n");
      }*/

    end = omp_get_wtime();
    printf("Done with data exchange in %f s\nMultiplying with my key.\n", end-start);

    EC_POINT **serverKeys = initECPoints(n, group);
    start = omp_get_wtime();
    mulPointsSecret(group, serverKeys, serverKeyedPoints, inv, n);
    end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with removing mask in: %f s\n", end-start);

    start = omp_get_wtime();
    mulPointsSecret(group, maskedServerOPRFOutput, serverOPRFOutput, clientSecret, n);
    end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with secret mult in: %f s\n", end-start);

    start = omp_get_wtime();
    findSame(group, maskedServerOPRFOutput, clientOPRFOutput, serverKeys, ciphertexts, inputStrings, n);
    end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with finding same elements: %f s\n", end-start);

    printf("Total time: %f s\n", ttime);


    // close the socket
    close(sockfd);

    /*    BN_free(a);
    BN_free(b);
    BN_free(p);*/

    BN_free(order);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}
