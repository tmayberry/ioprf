#include <openssl/obj_mac.h>
#include <openssl/ec.h>

int randomBNFromECGroup(EC_GROUP * group, BIGNUM * output, BN_CTX * ctx);
int generateECParameters(EC_GROUP *group, EC_POINT *g1, EC_POINT *g2, BN_CTX *ctx);
int generatePRFKey(BIGNUM ** p, int size, int bits);
int generateECEGKey(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * pk,  BN_CTX * ctx);
int encryptECEG(EC_GROUP * group, EC_POINT * g, EC_POINT * pk, BIGNUM * msg, EC_POINT * c, EC_POINT * epk, BN_CTX * ctx);
int decryptECEG(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * epk, EC_POINT * c, BIGNUM * m, BN_CTX * ctx);
int generateParameters(BIGNUM * p, BIGNUM * g1, BIGNUM * g2, BN_CTX * ctx);
int generateEGKey(BIGNUM * p, BIGNUM * g, BIGNUM * sk, BIGNUM * pk, BN_CTX * ctx);
int encryptEG(BIGNUM * p, BIGNUM * g, BIGNUM * pk, BIGNUM * m, BIGNUM * c, BIGNUM * epk, BN_CTX * ctx);
int decryptEG(BIGNUM * p, BIGNUM * g, BIGNUM * sk, BIGNUM * epk, BIGNUM * c, BIGNUM * m, BN_CTX * ctx);