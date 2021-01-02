#include <stdio.h>
#include "ioprf.h"
#include "util.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

//Creates size number of random BIGNUMs, each bits length long, and stores them in p
int generatePRFKey(BIGNUM ** p, int size, int bits){
    for(int x = 0; x < size; x++){
        BN_rand(p[x], bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }
    return 0;
}

