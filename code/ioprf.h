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
    BIGNUM * r0;
    BIGNUM * r1;
    BIGNUM * r2;
    BIGNUM * r3;
    BIGNUM * T0;
    BIGNUM * T1;
    BIGNUM * U0;
    BIGNUM * U1;
    BN_CTX * ctx;
} RECEIVERSTATE;



DHGROUP * chooseGroupParameters(BN_CTX * ctx);
int generatePRFKey(BIGNUM ** a, BIGNUM ** b, int size, int bits);
RECEIVERSTATE * initializeReceiver(DHGROUP * group, BN_CTX * ctx);
int receiverStep1(DHGROUP * group, unsigned int x, RECEIVERSTATE * state, BN_CTX * ctx);
int senderStep2(DHGROUP * group, BIGNUM * alpha, BIGNUM * beta, BIGNUM * T0, BIGNUM * T1, BIGNUM * U0, BIGNUM * U1, BIGNUM * X0, BIGNUM * X1, BIGNUM * Y0, BIGNUM * Y1, BN_CTX * ctx);
int receiverStep3(DHGROUP * group, unsigned int x, RECEIVERSTATE * state, BIGNUM * X0, BIGNUM * X1, BIGNUM * Y0, BIGNUM * Y1, BN_CTX * ctx);
char * calculatePRF(DHGROUP * group, RECEIVERSTATE * state, BN_CTX * ctx);
char * hashBN(BIGNUM * number);