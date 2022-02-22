#include <stdio.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#include "util.h"

#include "emp-tool/emp-tool.h"
using namespace std;
using namespace emp;

//Send and receive data
void mySend(NetIO * io, const void *data, size_t length) {
    io->send_data(&length, sizeof(length));
    io->send_data(data, length);
}

void myRecv(NetIO * io, void **data, size_t *length) {
    io->recv_data(length, sizeof(size_t));
    *data = (void *) malloc(*length);
    io->recv_data(*data, *length);
}


//Convert EC point to byte array
void point2BA(unsigned char **buf, size_t *length, EC_POINT * p, EC_GROUP * group, BN_CTX * ctx) {

    *length = EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    *buf = (unsigned char *) malloc(*length);
    EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, *buf, *length, ctx);

}

//Convert byte array to EC point
void BA2point(EC_POINT **point, unsigned char *buf, size_t length, EC_GROUP * group, BN_CTX * ctx) {

    *point = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, *point, buf, length, ctx)!=1) {
        cout <<"BA2point conversion error"<<endl;
    }

}

//Receive data over network and convert to point
void receivePoint(NetIO *io, EC_POINT **point, EC_GROUP * group, BN_CTX * ctx) {
    unsigned char *buffer;
    size_t length;
    myRecv(io, (void**) &buffer, &length);
    BA2point(point, buffer, length, group, ctx);
    free (buffer);
}

//Convert point to BA and send over network
void sendPoint(NetIO *io, EC_POINT * point, EC_GROUP * group, BN_CTX * ctx) {

    size_t length;
    unsigned char *buf;
    point2BA(&buf, &length, point, group, ctx);
    mySend(io, buf, length);
    free(buf);
}

//Generate a random BIGNUM from the numbers [1,N-1] where N is the size of the group
int randomBNFromECGroup(EC_GROUP * group, BIGNUM * output, BN_CTX * ctx) {
    BIGNUM *order;
    order = BN_new();

    //Get the order of the group
    EC_GROUP_get_order(group, order, ctx);

    BN_priv_rand_range(output, order);

    BN_free(order);

    return 0;
}

int randomBNFromPrimeGroup(BIGNUM * p, BIGNUM * output, BN_CTX * ctx) {
    BN_rand_range(output, p);
    BN_mod_sqr(output, output, p, ctx);
    return 0;
}

//Creates the two generators g1 and g2 for an elliptic curve
//g1 and g2 must be initialized EC_POINT objects
int generateECParameters(EC_GROUP **group, EC_POINT **g1, EC_POINT **g2, BN_CTX *ctx) {
    int ok = 0;
    BIGNUM *k;

    *group = EC_GROUP_new_by_curve_name(NID_secp224r1);

    *g1 = EC_POINT_new(*group);
    *g2 = EC_POINT_new(*group);

    k = BN_new();

    //Computing these generators should be done once by a trusted party.
    //Choose a random number k (this can be 0 with negligible chance, we won't worry about it)
    //Multiply generator by k to get a new random generator
    //g1 could be 1 or -1 but only with negligible chance so again we won't worry about it
    randomBNFromECGroup(*group, k, ctx);
    EC_POINT_mul(*group,*g1,k,NULL,NULL,ctx);

    //Repeat again for second generator
    randomBNFromECGroup(*group, k, ctx);
    EC_POINT_mul(*group,*g2,k,NULL,NULL,ctx);

    BN_free(k);

    return 0;
}

//Generates a random public/secret keypair on the specified curve with the specified generator
int generateECEGKey(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * pk,  BN_CTX * ctx) {
    //Generate random number in Z_p, store as sk
    randomBNFromECGroup(group, sk, ctx);
    //Generate public key = sk * g
    EC_POINT_mul(group,pk,NULL,g,sk,ctx);

    return 0;
}

//Encrypt msg with public key pk, using generator g, store ciphertext as c and the ephemeral public key as epk
int encryptECEG(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, EC_POINT * pk, BIGNUM * msg, EC_POINT * c, EC_POINT * epk, BN_CTX * ctx)
{
    BIGNUM * r = BN_new();

    encryptECEGwithR(group, g1, g2, pk, msg, c, epk, r, ctx);

    BN_free(r);

    return 0;
}

int decryptECEG(EC_GROUP * group, EC_POINT * g, BIGNUM * sk, EC_POINT * epk, EC_POINT * c, BIGNUM * m, BN_CTX * ctx) {
    //Recover shared key
    EC_POINT * sharedKey = EC_POINT_new(group);
    EC_POINT_mul(group, sharedKey, NULL, epk, sk, ctx);

    //Decrypt point
    EC_POINT * msgpoint = EC_POINT_new(group);
    EC_POINT_invert(group, sharedKey, ctx);
    EC_POINT_add(group, msgpoint, c, sharedKey, ctx);

    //Recover BIGNUM message
    EC_POINT_point2bn(group, g, POINT_CONVERSION_UNCOMPRESSED, m, ctx);

    EC_POINT_free(sharedKey);
    EC_POINT_free(msgpoint);

    return 0;
}


//Generate ElGamal public and secret keys for group with generator g
int generateEGKey(BIGNUM * p, BIGNUM * g, BIGNUM * sk, BIGNUM * pk, BN_CTX * ctx) {
    BN_rand_range(sk, p);
    BN_mod_exp(pk, g, sk, p, ctx);

    return 0;
}



void printBytes(unsigned char * b, int length) {
    for(int i = 0; i < length; i++) {
        printf("%x", b[i]);
    }
    printf("\n");
}

void createParameterFile()
{
    EC_GROUP * group;
    BN_CTX * ctx = BN_CTX_new();
    EC_POINT *g1, *g2;

    generateECParameters(&group, &g1, &g2, ctx);

    int size1 = EC_POINT_point2oct(group, g1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    int size2 = EC_POINT_point2oct(group, g2, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);

    unsigned char * g1bytes = (unsigned char *) malloc(size1);
    unsigned char * g2bytes = (unsigned char *) malloc(size2);

    EC_POINT_point2oct(group, g1, POINT_CONVERSION_UNCOMPRESSED, g1bytes, size1, ctx);
    EC_POINT_point2oct(group, g2, POINT_CONVERSION_UNCOMPRESSED, g2bytes, size1, ctx);

    FILE * out = fopen("params.bin", "wb");

    unsigned char  length[] = {(unsigned char)size1};
    fwrite(length, 1, 1, out);
    fwrite(g1bytes, size1, 1, out);

    length[0] = (unsigned char)size2;
    fwrite(length, 1, 1, out);
    fwrite(g2bytes, size2, 1, out);

    fclose(out);
    BN_CTX_free(ctx);
    free(g1bytes);
    free(g2bytes);
    EC_POINT_free(g1);
    EC_POINT_free(g2);
    EC_GROUP_free(group);
}

//Reads the file params.bin and gets the 2 generator points
//Uses fixed curve
int readParameterFile(EC_GROUP ** group, EC_POINT ** g1, EC_POINT ** g2, BN_CTX * ctx) {
    *group = EC_GROUP_new_by_curve_name(NID_secp224r1);

    *g1 = EC_POINT_new(*group);
    *g2 = EC_POINT_new(*group);

    FILE * in = fopen("params.bin", "rb");
    if(in == NULL) {
        printf("Must run ./test gen to generate the parameter file\n");
        return -1;
    }
    unsigned char * length = (unsigned char *) malloc(1);
    fread(length, 1, 1, in);

    unsigned char * gbytes = (unsigned char *) malloc(length[0]);
    fread(gbytes, length[0], 1, in);

    EC_POINT_oct2point(*group, *g1, gbytes, length[0], ctx);

    fread(length, 1, 1, in);
    fread(gbytes, length[0], 1, in);

    EC_POINT_oct2point(*group, *g2, gbytes, length[0], ctx);

    fclose(in);

    return 0;
}

int encryptECEGwithR(EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, EC_POINT * pk, BIGNUM * msg, EC_POINT * c, EC_POINT * epk, BIGNUM * r, BN_CTX * ctx)
{
    //Generate ephemeral public key
    randomBNFromECGroup(group, r, ctx);
    EC_POINT_mul(group, epk, NULL, g1, r, ctx);

    //Generate ciphertext
    EC_POINT_mul(group, c, NULL, pk, r, ctx);
    // if( ! BN_is_zero(msg) )
    // {
    //Convert msg to an EC point
    EC_POINT * msgpoint = EC_POINT_new(group);
    EC_POINT_mul(group, msgpoint, NULL, g2, msg, ctx);

    EC_POINT_add(group, c, c, msgpoint, ctx);
    EC_POINT_free(msgpoint);
    // }

    return 0;
}

int bnFromInt(unsigned int x, BIGNUM * bn) {
    BN_lebin2bn((unsigned char*)(&x), 4, bn);

    return 0;
}

void BNToBA(unsigned char **buf, BIGNUM *src, size_t *length) {
    *length = BN_num_bytes(src);
    *buf = (unsigned char*) malloc(*length);
    if (BN_bn2bin(src, *buf)!=(int)*length) {
        printf("BNToBA error\n");
    }
}

void sendBN(NetIO *io, BIGNUM *num) {
    unsigned char *buf;
    size_t length;
    BNToBA(&buf, num, &length);

    mySend(io, buf, length);

    free(buf);
}

void BAToBN(BIGNUM *dest, unsigned char *src, size_t length) {
    if (BN_bin2bn(src, length, dest)==NULL) {
        printf("BAToBN error\n");
    }
}

void receiveBN(NetIO *io, BIGNUM *num) {
    unsigned char *buffer;
    size_t length;
    myRecv(io, (void**) &buffer, &length);
    BAToBN(num, buffer, length);
}

void printPoint(EC_POINT *point, EC_GROUP * group) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL)) {
        BN_print_fp(stdout, x);
        putc('\n', stdout);
    }
    BN_free(x);
    BN_free(y);

}


