#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include "util.h"

typedef struct receiverstate{
    BIGNUM * sk;
    BIGNUM * pk;
    BIGNUM * V0;
    BIGNUM * V1;
    BIGNUM * D0;
    BIGNUM * D1;
    BIGNUM * T0;
    BIGNUM * T1;
    BIGNUM * U0;
    BIGNUM * U1;
    BN_CTX * ctx;
} RECEIVERSTATE;

typedef struct senderstate{
    BIGNUM ** a;
    BIGNUM ** b;
} SENDERSTATE;



DHGROUP * chooseGroupParameters(BN_CTX * ctx);
SENDERSTATE * initializeSender(int size, int bits);
RECEIVERSTATE * initializeReceiver(DHGROUP * group, BN_CTX * ctx);
int receiverStep1(DHGROUP * group, unsigned int x, RECEIVERSTATE * state, BN_CTX * ctx);
int senderStep2(DHGROUP * group, BIGNUM * alpha, BIGNUM * beta, BIGNUM * T0, BIGNUM * T1, BIGNUM * U0, BIGNUM * U1, BIGNUM * X0, BIGNUM * X1, BIGNUM * Y0, BIGNUM * Y1, BN_CTX * ctx);
int receiverStep3(DHGROUP * group, unsigned int x, RECEIVERSTATE * state, BIGNUM * X0, BIGNUM * X1, BIGNUM * Y0, BIGNUM * Y1, BN_CTX * ctx);
unsigned char * receiverPRF(DHGROUP * group, RECEIVERSTATE * state, BN_CTX * ctx);
unsigned char * hashBN(BIGNUM * number);
unsigned char * senderPRF(DHGROUP * group, SENDERSTATE * s, int * x, int length, BN_CTX * ctx);