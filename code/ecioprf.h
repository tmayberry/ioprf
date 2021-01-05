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
  
    //Intermediate values c, c', d and d'
    EC_POINT *c0, *c1, *cp0, *cp1, *d0, *d1, *dp0, *dp1;
 
    EC_POINT * g1;
    EC_POINT * g2;
    BN_CTX * ctx;
    EC_GROUP * group;
  
} RECEIVERSTATE;

typedef struct senderstate{
  EC_POINT * X0, *X1, *Y0, *Y1;
  EC_POINT * T0, *T1, *U0, *U1;
  
    BIGNUM ** a;
    BIGNUM ** b;
    EC_GROUP * group;
    EC_POINT * g2;
  BN_CTX * ctx;
} SENDERSTATE;


SENDERSTATE * initializeSender(EC_GROUP * group, EC_POINT * g2, int size, int bits);
RECEIVERSTATE * initializeReceiver(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2);
int receiverStep1(unsigned int x, RECEIVERSTATE * state);
int senderStep2(SENDERSTATE *s, int index);
int receiverStep3(unsigned int x, RECEIVERSTATE * state, EC_POINT * X0, EC_POINT * X1, EC_POINT * Y0, EC_POINT * Y1);
unsigned char * receiverPRF(RECEIVERSTATE * state);
unsigned char * hashPoint(EC_GROUP * group, EC_POINT * number, BN_CTX * ctx);
unsigned char * senderPRF(SENDERSTATE * s, int * x, int length);
int senderStep1c(SENDERSTATE *s, EC_POINT * c0, EC_POINT *c1, EC_POINT *cp0, EC_POINT *cp1, EC_POINT *d0, EC_POINT *d1, EC_POINT *dp0, EC_POINT *dp1);
