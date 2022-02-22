#define PROVER 1
#define VERIFIER 2

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include "ecioprf.h"


//Pedersen commitment
void commit(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * m, EC_POINT * com, BIGNUM * r, BN_CTX * ctx);
int verifyCommitment(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * m, EC_POINT * c, BIGNUM * r, BN_CTX * ctx);

//Zeroes the ciphertext c (adds g2*-m) for use in a plaintext ZKP, stores encryption of zero in c2
void zeroCiphertext(EC_GROUP * group, EC_POINT * g2, EC_POINT * c, BIGNUM * msg, EC_POINT * c2, BN_CTX * ctx);

//Prover first step of proof of plaintext
//Inputs: group, u1, u2, u3, u4
//Outputs: rho, t1, t2
void proofOfEncryptionStep1(EC_GROUP * group, EC_POINT * u1, EC_POINT * u2, EC_POINT * u3, EC_POINT * u4, EC_POINT * t1, EC_POINT * t2, BIGNUM * rho, BN_CTX * ctx);

//Prover third step of proof of plaintext
//Inputs: group, e, rho, r
//Outputs: s
void proofOfEncryptionStep3(EC_GROUP * group, BIGNUM * e, BIGNUM * rho, BIGNUM * r, BIGNUM * s, BN_CTX * ctx);

//Verifier fourth step of proof of plaintext
//Inputs: group, u1, u2, u3, u4, s, e, t1, t2
//Return: 1 if verifies successfully, 0 if not
int proofOfEncryptionStep4(EC_GROUP * group, EC_POINT * u1, EC_POINT * u2, EC_POINT * u3, EC_POINT * u4, BIGNUM * s, BIGNUM * e, EC_POINT * t1, EC_POINT * t2, BN_CTX * ctx);

//Prover first step of proof of knowledge of plaintext
//Inputs: group, g1, g
//Outputs: rho1, rho2, t
void proofOfKnowledgeStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * rho1, BIGNUM * rho2, EC_POINT * t, BN_CTX * ctx);

//Verifier second step of proof of knowledge of plaintext
//Inputs: group
//Outputs: e
void proofOfKnowledgeStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx);

//Prover third step of proof of knowledge of plaintext
//Inputs: group, rho1, rho2, e, r, m
//Outputs: s1, s2
void proofOfKnowledgeStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * e, BIGNUM * r, BIGNUM * s1, BIGNUM * s2, BIGNUM * m, BN_CTX * ctx);

//Prover third step of proof of knowledge of plaintext
//Inputs: group, g1, g, s1, s2, com, e, t
//Returns: 1 if verification successful, 0 if not
int proofOfKnowledgeStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * s1, BIGNUM * s2, EC_POINT * com, BIGNUM * e, EC_POINT * t, BN_CTX * ctx);

int parallelProofOfPTKnowledge(NetIO *io, BN_CTX * ctx, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, int party, EC_POINT **com, BIGNUM **msg, BIGNUM **comr, int n);
int proofOfPTKnowledge(NetIO *io, BN_CTX * ctx, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, int party, EC_POINT *com, BIGNUM *msg, BIGNUM *comr);

void ZKPoKStep1Prover(NetIO *io, BIGNUM * rho, EC_POINT ** commitToE, EC_POINT * g, EC_GROUP * group, BN_CTX * ctx, EC_POINT * g1);
void ZKPoKStep1Verifier(NetIO *io, EC_POINT ** g, BIGNUM * e, BIGNUM * r, EC_GROUP * group, BN_CTX * ctx, EC_POINT *g1);

void ZKPoKStep1VerifierParallel(NetIO *io, EC_POINT ** g, BIGNUM ** e, BIGNUM ** r, EC_GROUP * group, BN_CTX * ctx, EC_POINT *g1, int n);
void ZKPoKStep1ProverParallel(NetIO *io, BIGNUM ** rho, EC_POINT ** commitToE, EC_POINT ** g, EC_GROUP * group, BN_CTX * ctx, EC_POINT * g1, int n);

//Prover first step of proof of plaintext bit
//Inputs: group, g1, x, c
//Outputs: e1, rho, rhop, t1, t2
void proofOfPlaintextBitStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, unsigned int x, EC_POINT * c,  BIGNUM * e1, BIGNUM * e2, BIGNUM * rho, BIGNUM * rhop, EC_POINT * t1, EC_POINT * t2, BN_CTX * ctx);

//Verifier second step of proof of plaintext bit
//Inputs: group
//Outputs: e
void proofOfPlaintextBitStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx);

//Prover third step of proof of plaintext bit
//Inputs: group, g1, e1, e, rho, r
//Outputs: e2, s1
void proofOfPlaintextBitStep3(EC_GROUP * group, unsigned int x, BIGNUM * e1, BIGNUM * e, BIGNUM * rho, BIGNUM * rhop, BIGNUM * r, BIGNUM * e2, BIGNUM * s1, BIGNUM * s2, BN_CTX * ctx);

//Verifier fourth step of proof of plaintext bit
//Inputs: group, g1, x, c
//Returns: 1 if verifies successfully
int proofOfPlaintextBitStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * e, BIGNUM * e1, BIGNUM * e2, BIGNUM * s1, BIGNUM * s2, EC_POINT * t1, EC_POINT * t2, EC_POINT * c, BN_CTX * ctx);

int verifyCommitments(NetIO *io, int ell, RECEIVERSTATE * rs, EC_POINT ** com);
int proveCommitments(NetIO *io, SENDERSTATE * ss, int ell, BIGNUM ** com_r_alpha_beta);

int proveBit(NetIO *io, int x, EC_POINT * com, BIGNUM * r, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx);
int verifyBit(NetIO *io, EC_POINT **com, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx);

void proofOfEncryptionStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx);

int proveEnc(NetIO *io, EC_POINT *pk, EC_POINT *epk, EC_POINT *c, BIGNUM *r_enc, BIGNUM *msg, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx);
int verifyEnc(NetIO *io, EC_POINT *pk, EC_POINT *epk, EC_POINT *c, BIGNUM *msg, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx);

//Prover first step of proof of shuffle
//Inputs: group, g1, g2, pk, A, B
//Outputs: t1, t2, t3, rho1, rho2, rho3
void proofOfShuffleStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * pk, EC_POINT * A, EC_POINT * B, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * rho3, BN_CTX * ctx);

//Verifier second step of proof of shuffle
//Inputs: group
//Outputs: e
void proofOfShuffleStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx);


//Prover third step of proof of shuffle
//Inputs: group, rho1, rho2, rho3, e, x
//Outputs: s1, s2, s3
void proofOfShuffleStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * rho3, BIGNUM * e, BIGNUM *x, BIGNUM * r, BIGNUM * rprime, BIGNUM * s1, BIGNUM * s2, BIGNUM * s3, BN_CTX * ctx);

//Verifier fourth step of proof of shuffle
//Inputs: group, g1, g, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com
//Returns: 1 if verifies successfully
int proofOfShuffleStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * pk, EC_POINT * A, EC_POINT * B, EC_POINT * C, EC_POINT * D, BIGNUM * s1, BIGNUM * s2, BIGNUM * s3, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * e, EC_POINT * com, BN_CTX * ctx);

int proveShuffle(NetIO *io, EC_POINT *pk, BIGNUM * x, BIGNUM *one_minus_x, BIGNUM *r_com_x_i, BIGNUM *r_com_one_minus_x_i, BIGNUM **randomize_r, EC_POINT * V0, EC_POINT * V1, EC_POINT * D0, EC_POINT * D1, EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx);

int verifyShuffle(NetIO *io, EC_POINT *pk, EC_POINT *V0, EC_POINT *V1, EC_POINT *D0, EC_POINT *D1, EC_POINT *c0, EC_POINT *c1, EC_POINT *cp0, EC_POINT *cp1, EC_POINT *d0, EC_POINT *d1,EC_POINT *dp0, EC_POINT *dp1, EC_POINT *com_x, EC_POINT *com_one_minus_x,  EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx);

//Prover first step of proof of shuffle
//Inputs: group, g1, g2, A, B
//Outputs: t1, t2, t3, rho1, rho2
void proofOfMultiplicationStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * A, EC_POINT * B, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * rho1, BIGNUM * rho2, BN_CTX * ctx);

//Verifier second step of proof of shuffle
//Inputs: group
//Outputs: e
void proofOfMultiplicationStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx);


//Prover third step of proof of shuffle
//Inputs: group, rho1, rho2, e, x, r
//Outputs: s1, s2
void proofOfMultiplicationStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * e, BIGNUM *  x, BIGNUM * r, BIGNUM * s1, BIGNUM * s2, BN_CTX * ctx);

//Verifier fourth step of proof of shuffle
//Inputs: group, g1, g, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com
//Returns: 1 if verifies successfully
int proofOfMultiplicationStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * A, EC_POINT * B, EC_POINT * C, EC_POINT * D, BIGNUM * s1, BIGNUM * s2, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * e, EC_POINT * com, BN_CTX * ctx);
int proveMul(NetIO *io,  EC_POINT *A,  EC_POINT *B, BIGNUM *factor, BIGNUM *com_r, EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx);
int verifyMul(NetIO *io, EC_POINT *A, EC_POINT *B, EC_POINT *C, EC_POINT *D, EC_POINT *com, EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx);

int verifyReX(NetIO *io, RECEIVERSTATE *rs, EC_POINT *com_alpha_beta, EC_POINT *com_alpha_betap);
int proveReX(NetIO *io, SENDERSTATE *ss, EC_POINT *receiver_pk, BIGNUM *alpha_beta_i, BIGNUM *com_r_alpha_beta, BIGNUM *r_renc, BIGNUM *alpha_beta_ip, BIGNUM *com_r_alpha_betap, BIGNUM *r_rencp);
