#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <omp.h>

#include "psi-lib.h"
#include "net.h"



int main(int argc, char **argv)
{
    if (argc<3) {
        printf("Need n as 1st parameter, and server file name as second.\n");
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

    BIGNUM **serverSet = initBN(n);
    BIGNUM **serverSetMasked = initBN(n);

    BIGNUM *serverSecret = BN_new();
    fillRandom(&serverSecret, order, 1);

    BIGNUM *serverKeySecret = BN_new();
    fillRandom(&serverKeySecret, order, 1);
    BIGNUM **serverSetMaskedKey = initBN(n);


    EC_POINT **serverOPRFOutput = initECPoints(n, group);
    EC_POINT **clientOPRFOutput = initECPoints(n, group);
    EC_POINT **clientOPRFInput = initECPoints(n, group);

    EC_POINT **serverKeyPoints = initECPoints(n, group);


    printf("Done with init\n");

    fillRandom(serverSet, order, n);

    unsigned char *plaintexts = malloc(n*PLAINTEXT_LENGTH);
    fetchFile(NULL, serverSet, f, plaintexts, n, SERVER, order, ctx);
    fclose(f);
    printf("Done reading file\n");

    mulBN(serverSetMasked, serverSet, serverSecret, order, n);
    mulBN(serverSetMaskedKey, serverSet, serverKeySecret, order, n);

    printf("Done with both secret multiplications\n");

    double ttime = 0.0;
    double start = omp_get_wtime();
    mulPointsGenerator(group, serverKeyPoints, serverSetMaskedKey, n);
    double end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with secret key (2) multiplications\n");

    unsigned char *ciphertexts = malloc(n*CIPHERTEXT_LENGTH);
    
    start = omp_get_wtime();
    encrypt(group, ciphertexts, plaintexts, serverKeyPoints, n);
    end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with encrypting plaintexts in: %f s\n", end-start);

    start = omp_get_wtime();
    mulPointsGenerator(group, serverOPRFOutput, serverSetMasked, n);
    end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with set multiplication in: %f s\n\nWaiting for connection...", end-start);

    //bind socket
    int connfd, sockfd;
    myServer(&connfd, &sockfd);
    // Receive their points
    printf("Receiving client points...\n");
    receivePoints(connfd, clientOPRFInput, n, group);

    printf("Multiplying with my (first) key\n");
    start = omp_get_wtime();
    mulPointsSecret(group, clientOPRFOutput, clientOPRFInput, serverSecret, n);
    end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with (first) secret mult in: %f s\n", end-start);

    EC_POINT **clientOPRFOutputKey = initECPoints(n, group);
    printf("Multiplying with my (second) key\n");
    start = omp_get_wtime();
    mulPointsSecret(group, clientOPRFOutputKey, clientOPRFInput, serverKeySecret, n);
    end = omp_get_wtime();
    ttime += (end-start);
    printf("Done with (second) secret mult in: %f s\n", end-start);

    printf("Sending my points...\n");
    sendPoints(connfd, serverOPRFOutput, n, group, ctx);

    printf("Sending client points back...\n");
    sendPoints(connfd, clientOPRFOutput, n, group, ctx);

    printf("Sending my points keyed back...\n");
    sendPoints(connfd, clientOPRFOutputKey, n, group, ctx);

    printf("Sending ciphertexts...\n");
    sendData(connfd, ciphertexts, n * CIPHERTEXT_LENGTH);

    // After chatting, close socket
    close(sockfd);
    close(connfd);

    BN_free(order);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}
