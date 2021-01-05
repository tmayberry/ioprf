#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include "emp-tool/emp-tool.h"

using namespace emp;


int randomBNFromPrimeGroup(BIGNUM * p, BIGNUM * output, BN_CTX * ctx);
int randomBNFromECGroup(EC_GROUP * group, BIGNUM * output, BN_CTX * ctx);
int generateECParameters(EC_GROUP **group, EC_POINT **g1, EC_POINT **g2, BN_CTX *ctx);
int generateECEGKey(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * pk,  BN_CTX * ctx);
int encryptECEG(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, EC_POINT * pk, BIGNUM * msg, EC_POINT * c, EC_POINT * epk, BN_CTX * ctx);
int decryptECEG(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * epk, EC_POINT * c, BIGNUM * m, BN_CTX * ctx);
int generateEGKey(BIGNUM * p, BIGNUM * g, BIGNUM * sk, BIGNUM * pk, BN_CTX * ctx);
void printBytes(unsigned char * b, int length);
int readParameterFile(EC_GROUP ** group, EC_POINT ** g1, EC_POINT ** g2, BN_CTX * ctx);
void createParameterFile();
void point2BA(unsigned char **buf, size_t *length, EC_POINT * p, EC_GROUP * group, BN_CTX * ctx);
void mySend(NetIO * io, const void *data, size_t length);
void myRecv(NetIO * io, void **data, size_t *length);
void BA2point(EC_POINT **point, unsigned char *buf, size_t length, EC_GROUP * group, BN_CTX * ctx);
void receivePoint(NetIO *io, EC_POINT **point, EC_GROUP * group, BN_CTX * ctx);
void sendPoint(NetIO *io, EC_POINT * point, EC_GROUP * group, BN_CTX * ctx);
