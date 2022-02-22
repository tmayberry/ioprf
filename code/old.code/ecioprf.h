#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include "util.h"

typedef struct receiverstate{
    BIGNUM * sk;
    EC_POINT * pk;
    EC_POINT * V0;
    EC_POINT * V1;
    EC_POINT * D0;
    EC_POINT * D1;
    EC_POINT * T0;
    EC_POINT * T1;
    EC_POINT * U0;
    EC_POINT * U1;
    BN_CTX * ctx;
} RECEIVERSTATE;

typedef struct senderstate{
    BIGNUM ** a;
    BIGNUM ** b;
} SENDERSTATE;


SENDERSTATE * initializeSender(int size, int bits);
RECEIVERSTATE * initializeReceiver(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx);
int receiverStep1(EC_GROUP * group, EC_POINT * g1, unsigned int x, RECEIVERSTATE * state, BN_CTX * ctx);
int senderStep2(EC_GROUP * group, BIGNUM * alpha, BIGNUM * beta, EC_POINT * T0, EC_POINT * T1, EC_POINT * U0, EC_POINT * U1, EC_POINT * X0, EC_POINT * X1, EC_POINT * Y0, EC_POINT * Y1, BN_CTX * ctx);
int receiverStep3(EC_GROUP * group, EC_POINT * g1, unsigned int x, RECEIVERSTATE * state, EC_POINT * X0, EC_POINT * X1, EC_POINT * Y0, EC_POINT * Y1, BN_CTX * ctx);
unsigned char * receiverPRF(EC_GROUP * group, RECEIVERSTATE * state, BN_CTX * ctx);
unsigned char * hashPoint(EC_GROUP * group, EC_POINT * number, BN_CTX * ctx);
unsigned char * senderPRF(EC_GROUP * group, EC_POINT * g2, SENDERSTATE * s, int * x, int length, BN_CTX * ctx);