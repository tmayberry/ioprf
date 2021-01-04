#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <omp.h>


#include "psi-lib.h"
#include "net.h"


#define ENTROPY 128

void handleErrors(int error) {
    printf("error %d\n", error);
}


void fetchFile(char **inputStrings, BIGNUM **serverSet, FILE *f, unsigned char *plaintexts, unsigned long n, char party, BIGNUM *order, BN_CTX * ctx) {
    printf("Reading file...\n");

    char *lineptr = NULL;
    size_t len = 0;
    ssize_t read = 0;
    int i = 0;
    while ((i<n) && ((read = getline(&lineptr, &len, f)) != -1) ) {

        //Strip trailing newline
        if (lineptr[read-1]=='\n') {
            lineptr[read-1]=0;
            read--;
        }
        if (inputStrings) {
            inputStrings[i] = malloc(PLAINTEXT_LENGTH);
            memcpy(inputStrings[i], lineptr, PLAINTEXT_LENGTH);
        }

        /*for (int j=0;j<PLAINTEXT_LENGTH;j++) {
          printf("%c", lineptr[j]);
        }
        printf("-\n");
        exit(1);*/
        unsigned char hashValue[KEY_LENGTH];
        if (1!=hash(hashValue, (unsigned char *) lineptr, PLAINTEXT_LENGTH)) {
            printf("Hash problem\n");
            exit(1);
        }
        /*	for (int j = 0;j<KEY_LENGTH;j++) {
          printf("%02x", hashValue[j]);
        }
        printf("\n");
        */

        BN_bin2bn(hashValue, KEY_LENGTH, serverSet[i]);
        BN_mod(serverSet[i], serverSet[i], order, ctx);

        if (party == SERVER) {
            char delim[] = " ";
            char *ptr = strtok(lineptr, delim);
            ptr = strtok(NULL, delim);
            //printf("%s", ptr);

            //Strip trailing newline
            if ((ptr[strlen(ptr)-1]=='\n')||(ptr[strlen(ptr)-1]==' ')) {
                ptr[strlen(ptr)-1] = 0;
            }
            bzero(&plaintexts[i*PLAINTEXT_LENGTH], PLAINTEXT_LENGTH);
            strncpy((char*) &plaintexts[i*PLAINTEXT_LENGTH],ptr,PLAINTEXT_LENGTH);
            //plaintexts[i*PLAINTEXT_LENGTH+PLAINTEXT_LENGTH-1] = 0;
            //printf("%s-\n", &plaintexts[i*PLAINTEXT_LENGTH]);
        }
        i++;
    }

    if (lineptr) {
        free(lineptr);
    }

    /*  printSet(serverSet, n);
        exit(1);*/
}

void pointToKey(EC_GROUP *group, unsigned char *key, EC_POINT *point, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();


    EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx);
    unsigned char coordinate[BN_num_bytes(x)];
    BN_bn2bin(x, coordinate);

    if (1!=hash(key, coordinate, BN_num_bytes(x))) {
        printf("Hash problem\n");
        exit(1);
    }

    BN_free(x);
    BN_free(y);
}

void ECencrypt(EC_GROUP *group, unsigned char *ciphertexts, unsigned char *plaintexts, EC_POINT **serverKeyPoints, size_t n) {

    #pragma omp parallel
    {

    BN_CTX *ctx = BN_CTX_new();

    #pragma omp for
    for (int i=0; i<n; i++) {
        //Key
        unsigned char key[KEY_LENGTH];
        pointToKey(group, key, serverKeyPoints[i], ctx);

        //ECencrypt
        unsigned char *buff = &ciphertexts[i*CIPHERTEXT_LENGTH];
        unsigned char *iv = buff;
        unsigned char *tag = &buff[IV_LENGTH];
        unsigned char *ct = &buff[IV_LENGTH+AES_BLOCKSIZE];
        RAND_bytes(iv, IV_LENGTH);

        if (enc(&plaintexts[i*PLAINTEXT_LENGTH], PLAINTEXT_LENGTH, key, iv, ct, tag)<=0) {
            printf("Cannot encrypt\n");
            exit(1);
        }

    }

    BN_CTX_free(ctx);
    }
}



void fillRandom(BIGNUM **mySet, BIGNUM *p, int size) {
    #pragma omp parallel for
    for (unsigned long i=0; i<size; i++) {
        //BN_rand(mySet[i], ENTROPY, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BN_rand_range(mySet[i], p);
    }
}


BIGNUM **initBN(unsigned long size) {
    BIGNUM **set1 = malloc(size * sizeof(BIGNUM*));
    #pragma omp parallel for
    for (unsigned long i = 0; i<size; i++) {
        set1[i] = BN_new();
    }

    return set1;
}

erikBN *initeBN(unsigned long size) {
    erikBN *set1 = malloc(size * sizeof(erikBN));

    #pragma omp parallel for
    for (unsigned long i = 0; i<size; i++) {
        set1[i].num = BN_new();
        set1[i].pos = i;
    }

    return set1;
}


void printSet(BIGNUM **set1, unsigned long size) {
    for (unsigned long i = 0; i<size; i++) {
        char *tmp = BN_bn2dec(set1[i]);
        printf("%s\n", tmp);
        free(tmp);
    }
}


void merge(BIGNUM ** X, unsigned long size, BIGNUM ** tmp) {
    unsigned long i = 0;
    unsigned long j = size/2;
    unsigned long ti = 0;

    while (i<size/2 && j<size) {
        if (BN_cmp(X[i], X[j])==-1) {
            tmp[ti] = X[i];
            ti++;
            i++;
        } else {
            tmp[ti] = X[j];
            ti++;
            j++;
        }
    }

    while (i<size/2) { /* finish up lower half */
        tmp[ti] = X[i];
        ti++;
        i++;
    }
    while (j<size) { /* finish up upper half */
        tmp[ti] = X[j];
        ti++;
        j++;
    }

    for (unsigned long i=0; i<size; i++) {
        X[i] = tmp[i];
    }

}


void emerge(erikBN * X, unsigned long size, erikBN * tmp) {
    unsigned long i = 0;
    unsigned long j = size/2;
    unsigned long ti = 0;

    while (i<size/2 && j<size) {
        if (BN_cmp(X[i].num, X[j].num)==-1) {
            tmp[ti] = X[i];
            ti++;
            i++;
        } else {
            tmp[ti] = X[j];
            ti++;
            j++;
        }
    }

    while (i<size/2) { /* finish up lower half */
        tmp[ti] = X[i];
        ti++;
        i++;
    }
    while (j<size) { /* finish up upper half */
        tmp[ti] = X[j];
        ti++;
        j++;
    }

    for (unsigned long i=0; i<size; i++) {
        X[i] = tmp[i];
    }

}



void myMergeSort(BIGNUM ** X, unsigned long size, BIGNUM ** tmp)
{
    if (size < 2) return;

    myMergeSort(X, size/2, tmp);
    myMergeSort(X+(size/2), size-(size/2), tmp);

    merge(X, size, tmp);
}

void emyMergeSort(erikBN * X, unsigned long size, erikBN *tmp)
{
    if (size < 2) return;

    //pragma omp task shared(X, tmp)
    emyMergeSort(X, size/2, tmp);

    //pragma omp task shared(X, tmp)
    emyMergeSort(X+(size/2), size-(size/2), tmp+(size/2));

    //pragma omp taskwait
    emerge(X, size, tmp);

    //}
}



EC_POINT ** initECPoints(unsigned long size, EC_GROUP *group) {

    EC_POINT **tmp = malloc(size*sizeof(EC_POINT *));

    #pragma omp parallel for
    for (unsigned long i = 0; i<size; i++) {
        tmp[i] = EC_POINT_new(group);
    }

    return tmp;
}


void printScalar(BIGNUM *x) {
    char *tmp = BN_bn2dec(x);
    printf("%s\n", tmp);
    free(tmp);
}

void mulPointsGenerator(EC_GROUP *group, EC_POINT **points, BIGNUM **set1, unsigned long size) {

    #pragma omp parallel
    {
        BN_CTX * ctx = BN_CTX_new();
        #pragma omp for
        for (unsigned long i = 0; i<size; i++) {
            if (1 != EC_POINT_mul(group, points[i], set1[i], NULL, NULL, ctx))
                handleErrors(3);
        }

        BN_CTX_free(ctx);
    }

}

void mulPointsSecret (EC_GROUP *group, EC_POINT **dest, EC_POINT **src, BIGNUM *secret, unsigned long size) {

    #pragma omp parallel
    {
        BN_CTX * ctx = BN_CTX_new();

        #pragma omp for
        for (unsigned long i = 0; i<size; i++) {
            if (1 != EC_POINT_mul(group, dest[i], NULL, src[i], secret, ctx))
                handleErrors(5);
        }

        BN_CTX_free(ctx);
    }
}

void findSame(EC_GROUP *group, EC_POINT **points1, EC_POINT **points2, EC_POINT **serverKeys, unsigned char *ciphertexts, char **inputStrings, unsigned long size) {
    erikBN *myset = initeBN(2*size);

    #pragma omp parallel
    {
        BN_CTX * ctx = BN_CTX_new();
        BIGNUM *y = BN_new();

        #pragma omp for
        for (unsigned long i = 0;  i<size ; i++) {
            EC_POINT_get_affine_coordinates_GFp(group, points1[i], myset[i].num, y, ctx);
            EC_POINT_get_affine_coordinates_GFp(group, points2[i], myset[i+size].num, y, ctx);
        }
        BN_CTX_free(ctx);
        BN_free(y);
    }


    erikBN *tmp = initeBN(2*size);

    emyMergeSort(myset, 2*size, tmp);

    omp_lock_t matchSem, printSem;
    omp_init_lock(&matchSem);
    omp_init_lock(&printSem);

    unsigned long noMatch = 0;
    #pragma omp parallel
    {

        BN_CTX * ctx = BN_CTX_new();

        #pragma omp for
        for (unsigned long int i = 0; i<2*size-1; i++) {
            if (BN_cmp(myset[i].num,myset[i+1].num)==0) {
                if (myset[i].pos>=size) {
                    omp_set_lock(&matchSem);
                    noMatch++;
                    omp_unset_lock(&matchSem);

                    omp_set_lock(&printSem);
                    printf("Our pos %ld (%.*s) matches their %ld. Aux string is: ",  myset[i+1].pos+1, PLAINTEXT_LENGTH, inputStrings[myset[i+1].pos], myset[i].pos-size+1);

                    EC_POINT *point = serverKeys[myset[i].pos-size];
                    unsigned char  *ciphertext = &ciphertexts[CIPHERTEXT_LENGTH*(myset[i].pos-size)];
                    unsigned char plaintext[PLAINTEXT_LENGTH];
                    decrypt(group, plaintext, ciphertext, point, ctx);
                    printf("%.*s\n", PLAINTEXT_LENGTH, plaintext);
                    omp_unset_lock(&printSem);
                }
                else {
                    omp_set_lock(&matchSem);
                    noMatch++;
                    omp_unset_lock(&matchSem);

                    omp_set_lock(&printSem);
                    printf("Our pos %ld (%.*s) matches their %ld. Aux string is",  myset[i].pos+1, PLAINTEXT_LENGTH, inputStrings[myset[i].pos], myset[i+1].pos-size+1);

                    EC_POINT *point = serverKeys[myset[i+1].pos-size];
                    unsigned char  *ciphertext = &ciphertexts[CIPHERTEXT_LENGTH*(myset[i+1].pos-size)];
                    unsigned char plaintext[PLAINTEXT_LENGTH];
                    decrypt(group, plaintext, ciphertext, point, ctx);
                    printf("%.*s\n", PLAINTEXT_LENGTH, plaintext);
                    omp_unset_lock(&printSem);

                }
            }
        }
        BN_CTX_free(ctx);
    }
    printf("Number of matches: %ld\n", noMatch);

    omp_destroy_lock(&matchSem);
    omp_destroy_lock(&printSem);

}

void decrypt (EC_GROUP *group, unsigned char *plaintext, unsigned char *ciphertext, EC_POINT *point, BN_CTX * ctx) {
    unsigned char key[KEY_LENGTH];
    pointToKey(group, key, point, ctx);
    unsigned char *iv = ciphertext;
    unsigned char *tag = &ciphertext[IV_LENGTH];
    if (dec(&ciphertext[IV_LENGTH+AES_BLOCKSIZE], CIPHERTEXT_LENGTH, tag, key, iv, plaintext)<=0) {

    }
}

void printPoint (EC_GROUP *group, EC_POINT *point, BN_CTX * ctx) {

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)) {
        BN_print_fp(stdout, x);
        putc('\n', stdout);
    } else {
        printf("printPoint: cannot get affine coordinates.\n");
    }

    BN_free(x);
    BN_free(y);

}

void checkPoints(EC_GROUP *group, EC_POINT **points, unsigned long size) {

    BN_CTX * ctx = BN_CTX_new();


    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    for (unsigned long i = 0;  i<size ; i++) {
        if (EC_POINT_get_affine_coordinates_GFp(group, points[i], x, y, ctx)) {
            ;
        } else {
            printf("printPoints: cannot get affine coordinates of point %ld.\n", i);
            exit(1);
        }
    }
    BN_free(x);
    BN_free(y);



    BN_CTX_free(ctx);


}

void printPoints(EC_GROUP *group, EC_POINT **points, unsigned long size, BN_CTX * ctx) {
    if (size <=10) {
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();

        for (unsigned long i = 0;  i<size ; i++) {
            if (EC_POINT_get_affine_coordinates_GFp(group, points[i], x, y, ctx)) {
                BN_print_fp(stdout, x);
                putc('\n', stdout);
            } else {
                printf("printPoints: cannot get affine coordinates.\n");
            }
        }
        BN_free(x);
        BN_free(y);
    }
}

void mulBN(BIGNUM **dest, BIGNUM **source, BIGNUM *secret, BIGNUM *order, unsigned long size) {

    #pragma omp parallel
    {
        BN_CTX * ctx = BN_CTX_new();
        #pragma omp for
        for (unsigned long i = 0; i<size; i++) {
            BN_mod_mul(dest[i], source[i], secret, order, ctx);
        }
        BN_CTX_free(ctx);
    }
}


void sendPoints(int sockfd, EC_POINT ** points2, unsigned long size, EC_GROUP *group, BN_CTX * ctx) {

    size_t t;
    point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
    unsigned char *buf = malloc(57 * size);

    if (buf==NULL) {
        printf("malloc failed\n");
        exit(1);
    }
    for (unsigned long i = 0; i<size; i++) {
        t = EC_POINT_point2oct(group, points2[i],
                               form,  &buf[57*i], 57, ctx);
        if (t!=57) {
            printPoint(group, points2[i], ctx);
            printf("Wrong conversion when sending point %ld, size %ld.\n", i, t);
            exit(1);
        }

    }

    erikSend(sockfd, buf, size);

    free(buf);
    //  printPoints(group, points2, size, ctx);

}

void receivePoints(int sockfd, EC_POINT **points2, unsigned long size, EC_GROUP *group) {
    BN_CTX *ctx = BN_CTX_new();

    unsigned char *buff = malloc(57*size);
    if(buff==NULL) {
        printf("malloc failed\n");
        exit(1);
    }

    erikReceive(sockfd, buff, size);

    for (unsigned int i = 0; i<size; i++) {
        if (1!=EC_POINT_oct2point(group, points2[i],
                                  &buff[57*i], 57, ctx)) {
            printf("Conversion error while receiving\n");
            exit(1);
        }
    }

    free(buff);
    //printPoints(group, points2, size, ctx);
    BN_CTX_free(ctx);

}
