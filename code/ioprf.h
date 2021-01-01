#include <openssl/obj_mac.h>
#include <openssl/ec.h>


int generateParameters(EC_GROUP *group, EC_POINT *g1, EC_POINT *g2, BN_CTX *ctx);