#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define IV_LENGTH 12
#define AES_BLOCKSIZE 16
#define KEY_LENGTH 32

#define PLAINTEXT_LENGTH 10

#define CIPHERTEXT_LENGTH (IV_LENGTH+AES_BLOCKSIZE+PLAINTEXT_LENGTH)
#define SERVER 1
#define CLIENT 0

void fetchFile(char **inputStrings, BIGNUM **serverSet, FILE *f, unsigned char *plaintexts, unsigned long n, char party, BIGNUM *p, BN_CTX * ctx);
int dec(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *key, unsigned char *iv,unsigned char *plaintext);
void decrypt (EC_GROUP *group, unsigned char *plaintext, unsigned char *ciphertext, EC_POINT *key, BN_CTX * ctx);
void ECencrypt(EC_GROUP *group, unsigned char *ciphertexts, unsigned char *plaintexts, EC_POINT **serverKeyPoints, size_t n);
int hash(unsigned char* output, unsigned char *input, unsigned int len);
int enc(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);
void printSet(BIGNUM **set1, unsigned long size);
void mulPointsGenerator(EC_GROUP *curve, EC_POINT **points, BIGNUM **set1, unsigned long size);
void findSame(EC_GROUP *curve, EC_POINT **points1, EC_POINT **points2, EC_POINT **serverKeys, unsigned char *ciphertexts, char **inputStrings,  unsigned long size);
void mulBN(BIGNUM **dest, BIGNUM **source, BIGNUM *secret, BIGNUM *p, unsigned long size);
void fillRandom(BIGNUM **mySet, BIGNUM *p, int size);
void mulPointsSecret (EC_GROUP *group, EC_POINT **dst, EC_POINT **src, BIGNUM *secret, unsigned long size);
EC_POINT ** initECPoints(unsigned long size, EC_GROUP *curve);
void handleErrors(int error);
BIGNUM **initBN(unsigned long size);
void printPoints(EC_GROUP *curve, EC_POINT **points, unsigned long size, BN_CTX* ctx);
void printPoint (EC_GROUP *group, EC_POINT *point, BN_CTX * ctx);
void test(unsigned long n);
void receivePoints(int sockfd, EC_POINT **points2, unsigned long size, EC_GROUP *group);
void sendPoints(int sockfd, EC_POINT ** points2, unsigned long size, EC_GROUP *group, BN_CTX * ctx);

void checkPoints(EC_GROUP *group, EC_POINT **points, unsigned long size);
void printScalar(BIGNUM *x);

typedef struct
{
    unsigned long pos;
    BIGNUM *num;
} erikBN;

