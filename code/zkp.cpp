#include "zkp.h"

using namespace std;

//Computers Pedersen commitment for message m, stores output in c and r
void commit(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * m, EC_POINT * com, BIGNUM * r, BN_CTX * ctx) {
    randomBNFromECGroup(group, r, ctx);
    EC_POINT * temp = EC_POINT_new(group);

    EC_POINT_mul(group, temp, NULL, g, m, ctx);
    EC_POINT_mul(group, com, NULL, g1, r, ctx);

    EC_POINT_add(group, com, com, temp, ctx);

    EC_POINT_free(temp);
}


//Verifies Pedersen commitment
int verifyCommitment(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * m, EC_POINT * c, BIGNUM * r, BN_CTX * ctx) {
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);

    EC_POINT_mul(group, temp1, NULL, g, m, ctx);
    EC_POINT_mul(group, temp2, NULL, g1, r, ctx);

    EC_POINT_add(group, temp1, temp2, temp1, ctx);

    int cmp = EC_POINT_cmp(group, temp1, c, ctx);

    EC_POINT_free(temp1);
    EC_POINT_free(temp2);

    //    if(cmp == 0)
    //   return 1;
    //return 0;
    return 1-cmp;
}

//Zeroes the ciphertext c (adds g2*-m) for use in a plaintext ZKP, stores encryption of zero in c2
void zeroCiphertext(EC_GROUP * group, EC_POINT * g2, EC_POINT * c, BIGNUM * msg, EC_POINT * c2, BN_CTX * ctx) {
    EC_POINT * temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, NULL, g2, msg, ctx);
    EC_POINT_invert(group, temp, ctx);
    EC_POINT_add(group, c2, temp, c, ctx);
    EC_POINT_free(temp);
}

//Prover first step of proof of plaintext
//Inputs: group, u1, u2, u3, u4
//Outputs: rho, t1, t2
void proofOfEncryptionStep1(EC_GROUP * group, EC_POINT * u1, EC_POINT * u2, EC_POINT * u3, EC_POINT * u4, EC_POINT * t1, EC_POINT * t2, BIGNUM * rho, BN_CTX * ctx) {
    //Choose random rho in Z_p
    randomBNFromECGroup(group, rho, ctx);

    EC_POINT_mul(group, t1, NULL, u1, rho, ctx);
    EC_POINT_mul(group, t2, NULL, u3, rho, ctx);
}


//Prover third step of proof of plaintext
//Inputs: group, e, rho, r
//Outputs: s
void proofOfEncryptionStep3(EC_GROUP * group, BIGNUM * e, BIGNUM * rho, BIGNUM * r, BIGNUM * s, BN_CTX * ctx) {
    BIGNUM * order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BN_mod_mul(s, e, r, order, ctx);
    BN_mod_add(s, s, rho, order, ctx);

    BN_free(order);
}

//Verifier fourth step of proof of plaintext
//Inputs: group, u1, u2, u3, u4, s, e, t1, t2
//Return: 1 if verifies successfully, 0 if not
int proofOfEncryptionStep4(EC_GROUP * group, EC_POINT * u1, EC_POINT * u2, EC_POINT * u3, EC_POINT * u4, BIGNUM * s, BIGNUM * e, EC_POINT * t1, EC_POINT * t2, BN_CTX * ctx) {
    EC_POINT * left1, * right1, * left2, * right2;
    left1 = EC_POINT_new(group);
    left2 = EC_POINT_new(group);
    right1 = EC_POINT_new(group);
    right2 = EC_POINT_new(group);

    EC_POINT_mul(group, left1, NULL, u1, s, ctx);

    EC_POINT_mul(group, right1, NULL, u2, e, ctx);
    EC_POINT_add(group, right1, right1, t1, ctx);

    EC_POINT_mul(group, left2, NULL, u3, s, ctx);

    EC_POINT_mul(group, right2, NULL, u4, e, ctx);
    EC_POINT_add(group, right2, right2, t2, ctx);

    int firstcmp = EC_POINT_cmp(group, left1, right1, ctx);
    int secondcmp = EC_POINT_cmp(group, left2, right2, ctx);

    if(firstcmp == 0 && secondcmp == 0)
        return 1;
    return 0;
}

//Prover first step of proof of knowledge of plaintext
//Inputs: group, g1, g
//Outputs: rho1, rho2, t
void proofOfKnowledgeStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * rho1, BIGNUM * rho2, EC_POINT * t, BN_CTX * ctx) {
    EC_POINT * temp = EC_POINT_new(group);

    randomBNFromECGroup(group, rho1, ctx);
    randomBNFromECGroup(group, rho2, ctx);

    EC_POINT_mul(group, temp, NULL, g, rho2, ctx);
    EC_POINT_mul(group, t, NULL, g1, rho1, ctx);
    EC_POINT_add(group, t, temp, t, ctx);

    EC_POINT_free(temp);
}

//Verifier second step of proof of knowledge of plaintext
//Inputs: group
//Outputs: e
void proofOfKnowledgeStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx) {
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of knowledge of plaintext
//Inputs: group, rho1, rho2, e, r, m
//Outputs: s1, s2
void proofOfKnowledgeStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * e, BIGNUM * r, BIGNUM * s1, BIGNUM * s2, BIGNUM * m, BN_CTX * ctx) {
    BN_mul(s1, e, r, ctx);
    BN_add(s1, s1, rho1);

    BN_mul(s2, e, m, ctx);
    BN_add(s2, s2, rho2);
}

//Prover third step of proof of knowledge of plaintext
//Inputs: group, g1, g, s1, s2, com, e, t
//Returns: 1 if verification successful, 0 if not
int proofOfKnowledgeStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * s1, BIGNUM * s2, EC_POINT * com, BIGNUM * e, EC_POINT * t, BN_CTX * ctx) {
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);

    EC_POINT_mul(group, temp1, NULL, g1, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, g, s2, ctx);
    EC_POINT_mul(group, temp3, NULL, com, e, ctx);
    EC_POINT_add(group, temp3, temp3, t, ctx);
    EC_POINT_add(group, temp1, temp1, temp2, ctx);

    int ret = EC_POINT_cmp(group, temp1, temp3, ctx);


    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);

    if(ret == 0) {
        return 1;
    }
    return 0;
}

void ZKPoKStep1Prover(NetIO *io, BIGNUM * rho, EC_POINT ** commitToE, EC_POINT * g, EC_GROUP * group, BN_CTX * ctx, EC_POINT * g1) {

    //compute g=g_1^rho, send g, receive commitment from verifier

    randomBNFromECGroup(group, rho, ctx);
    EC_POINT_mul(group, g, NULL, g1, rho, ctx);

    sendPoint(io, g, group, ctx);

    receivePoint(io, commitToE, group, ctx);

}

void ZKPoKStep1Verifier(NetIO *io, EC_POINT ** g, BIGNUM * e, BIGNUM * r, EC_GROUP * group, BN_CTX * ctx, EC_POINT *g1) {

    //receive g, compute commitment using g, send commitment
    EC_POINT * com = EC_POINT_new(group);

    receivePoint(io, g, group, ctx);

    randomBNFromECGroup(group, e, ctx);
    commit(group, g1, *g, e, com, r, ctx);
    sendPoint(io, com, group, ctx);

    EC_POINT_free(com);
}

void ZKPoKStep1VerifierParallel(NetIO *io, EC_POINT ** g, BIGNUM ** e, BIGNUM ** r, EC_GROUP * group, BN_CTX * ctx, EC_POINT *g1, int n) {

    for (int i=0; i<n; i++) {
        receivePoint(io, &(g[i]), group, ctx);
    }
    EC_POINT * com = EC_POINT_new(group);
    for (int i=0; i<n; i++) {
        //receive g, compute commitment using g, send commitment

        randomBNFromECGroup(group, e[i], ctx);
        commit(group, g1, (g[i]), e[i], com, r[i], ctx);
        sendPoint(io, com, group, ctx);

    }
    EC_POINT_free(com);
}

void ZKPoKStep1ProverParallel(NetIO *io, BIGNUM ** rho, EC_POINT ** commitToE, EC_POINT ** g, EC_GROUP * group, BN_CTX * ctx, EC_POINT * g1, int n) {

    for (int i=0; i<n; i++) {
        //compute g=g_1^rho, send g, receive commitment from verifier

        randomBNFromECGroup(group, rho[i], ctx);
        EC_POINT_mul(group, g[i], NULL, g1, rho[i], ctx);

        sendPoint(io, g[i], group, ctx);
    }
    for (int i=0; i<n; i++) {
        receivePoint(io, &(commitToE[i]), group, ctx);
    }
}

//party, statement, witness
//party is either PROVER or VERIFIER
//run n proofs of plaintext knowledge in parallel
int parallelProofOfPTKnowledge(NetIO *io, BN_CTX * ctx, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, int party, EC_POINT **com, BIGNUM **msg, BIGNUM **comr, int n) {

    if (party == PROVER) {

        EC_POINT ** t = (EC_POINT **) malloc(n *sizeof(EC_POINT *));
        BIGNUM ** rho1 = (BIGNUM **) malloc(n *sizeof(BIGNUM *));
        BIGNUM ** rho2 = (BIGNUM **) malloc(n *sizeof(BIGNUM *));

        BIGNUM ** rhoForMalSec = (BIGNUM **) malloc(n *sizeof(BIGNUM *));
        EC_POINT ** g = (EC_POINT **) malloc(n *sizeof(EC_POINT *));
        EC_POINT ** verifierCommitment = (EC_POINT **) malloc(n *sizeof(EC_POINT *));


        for (int i = 0; i<n; i++) {
            rhoForMalSec[i] = BN_new();
            g[i] = EC_POINT_new(group);
        }


        ZKPoKStep1ProverParallel(io, rhoForMalSec, verifierCommitment, g, group, ctx, g1, n);


        //Send t
        for (int i = 0; i<n; i++) {
            t[i] = EC_POINT_new(group);
            rho1[i] = BN_new();
            rho2[i] = BN_new();

            proofOfKnowledgeStep1(group, g1, g2, rho1[i], rho2[i], t[i], ctx);
            sendPoint(io, t[i], group, ctx);
        }

        //Receive e,r
        BIGNUM ** e = (BIGNUM **) malloc(n*sizeof(BIGNUM*));
        BIGNUM ** r = (BIGNUM **) malloc(n*sizeof(BIGNUM*));
        for (int i = 0; i<n; i++) {
            e[i] = BN_new();
            r[i] = BN_new();
            receiveBN(io, e[i]);
            receiveBN(io, r[i]);
        }

        for (int i=0; i<n; i++) {
            if(verifyCommitment(group, g1, g[i], e[i], verifierCommitment[i], r[i], ctx)!=1) {
                cout <<"Verifier: cannot verify commitment to e"<<endl;
                exit(1);
            }
        }


        //Send s1, s2
        BIGNUM ** s1 = (BIGNUM**) malloc(n*sizeof(BIGNUM*));
        BIGNUM ** s2 = (BIGNUM**) malloc(n*sizeof(BIGNUM*));

        for (int i = 0; i<n; i++) {
            s1[i] = BN_new();
            s2[i] = BN_new();
            proofOfKnowledgeStep3(group, rho1[i], rho2[i], e[i], comr[i], s1[i], s2[i], msg[i], ctx);

            sendBN(io, s1[i]);
            sendBN(io, s2[i]);
            sendBN(io, rhoForMalSec[i]);
        }

        for (int i = 0; i<n; i++) {
            EC_POINT_free(t[i]);
            EC_POINT_free(g[i]);
            BN_free(rho1[i]);
            BN_free(r[i]);
            BN_free(rho2[i]);
            BN_free(s1[i]);
            BN_free(s2[i]);
            BN_free(e[i]);
            BN_free(rhoForMalSec[i]);
        }

        free(t);
        free(rho1);
        free(rho2);
        free(s1);
        free(s2);
        free(e);
        free(rhoForMalSec);
        free(g);
        free(verifierCommitment);
        free(r);

        return 1;

    } else { //VERIFIER


        EC_POINT **g = (EC_POINT **) malloc(n*sizeof(EC_POINT*));
        BIGNUM ** e = (BIGNUM **) malloc(n*sizeof(BIGNUM *));
        BIGNUM ** r = (BIGNUM**) malloc(n*sizeof(BIGNUM*));

        for (int i=0; i<n; i++) {
            e[i] = BN_new();
            r[i] = BN_new();
        }


        ZKPoKStep1VerifierParallel(io, g, e, r, group, ctx, g1, n);


        //Receive t
        EC_POINT ** t = (EC_POINT **) malloc(n*sizeof(EC_POINT *));
        for (int i=0; i<n; i++) {
            receivePoint(io, &(t[i]), group, ctx);
        }

        //Send e,r
        for (int i=0; i<n; i++) {
            sendBN(io, e[i]);
            sendBN(io, r[i]);
        }

        //Receive s1, s2
        int prod = 1;
        BIGNUM ** s1 = (BIGNUM **) malloc(n*sizeof(BIGNUM *));
        BIGNUM ** s2 = (BIGNUM **) malloc(n*sizeof(BIGNUM *));
        BIGNUM ** rhoForMalSec = (BIGNUM **) malloc(n*sizeof(BIGNUM *));
        for (int i=0; i<n; i++) {
            s1[i] = BN_new();
            s2[i] = BN_new();
            rhoForMalSec[i] = BN_new();

            receiveBN(io, s1[i]);
            receiveBN(io, s2[i]);
            receiveBN(io, rhoForMalSec[i]);

            prod *= proofOfKnowledgeStep4(group, g1, g2, s1[i], s2[i], com[i], e[i], t[i], ctx);


            //Verify rhoForMalSec
            EC_POINT * temp1 = EC_POINT_new(group);
            EC_POINT_mul(group, temp1, NULL, g1, rhoForMalSec[i], ctx);
            prod *=1-EC_POINT_cmp(group, temp1, g[i], ctx);

            EC_POINT_free(temp1);
            EC_POINT_free(t[i]);
            EC_POINT_free(g[i]);
            BN_free(s1[i]);
            BN_free(s2[i]);
            BN_free(e[i]);
            BN_free(r[i]);
            BN_free(rhoForMalSec[i]);
        }
        free(rhoForMalSec);
        free(t);
        free(s1);
        free(s2);
        free(e);
        free(r);
        free(g);

        return prod;
    }

}

int proofOfPTKnowledge(NetIO *io, BN_CTX * ctx, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, int party, EC_POINT *com, BIGNUM *msg, BIGNUM *comr) {
    //Proof of knowledge test

    if (party == PROVER) {
        EC_POINT * t = EC_POINT_new(group);
        BIGNUM * rho1 = BN_new();
        BIGNUM * rho2 = BN_new();

        BIGNUM * rhoForMalSec = BN_new();
        EC_POINT * g = EC_POINT_new(group);
        EC_POINT * verifierCommitment;
        ZKPoKStep1Prover(io, rhoForMalSec, &verifierCommitment, g, group, ctx, g1);
        //Send t
        proofOfKnowledgeStep1(group, g1, g2, rho1, rho2, t, ctx);
        sendPoint(io, t, group, ctx);

        //Receive (e,r), check correctness
        BIGNUM * e = BN_new();
        BIGNUM * r = BN_new();
        receiveBN(io, e);
        receiveBN(io, r);

        if(verifyCommitment(group, g1, g, e, verifierCommitment, r, ctx)!=1) {
            cout <<"Verifier: cannot verify commitment to e"<<endl;
            exit(1);
        }

        //Send s1, s2
        BIGNUM * s1 = BN_new();
        BIGNUM * s2 = BN_new();

        proofOfKnowledgeStep3(group, rho1, rho2, e, comr, s1, s2, msg, ctx);

        sendBN(io, s1);
        sendBN(io, s2);

        //Send rhoForMalSec to complete extractability
        sendBN(io, rhoForMalSec);

        EC_POINT_free(t);
        EC_POINT_free(verifierCommitment);
        BN_free(rho1);
        BN_free(rho2);
        BN_free(s1);
        BN_free(s2);
        BN_free(e);
        BN_free(rhoForMalSec);
        BN_free(r);

        return 0;

    } else { //VERIFIER

        BIGNUM * e = BN_new();
        BIGNUM * r = BN_new();

        EC_POINT *g;
        ZKPoKStep1Verifier(io, &g, e, r, group, ctx, g1);

        //Receive t
        EC_POINT * t;
        receivePoint(io, &t, group, ctx);

        //Second message of the regular protocol, open commitment to m
        sendBN(io, e);
        sendBN(io, r);

        BIGNUM * s1 = BN_new();
        BIGNUM * s2 = BN_new();
        BIGNUM * rhoForMalSec = BN_new();

        receiveBN(io, s1);
        receiveBN(io, s2);
        receiveBN(io, rhoForMalSec);

        int ret = proofOfKnowledgeStep4(group, g1, g2, s1, s2, com, e, t, ctx);

        //Verify rhoForMalSec
        EC_POINT * temp1 = EC_POINT_new(group);
        EC_POINT_mul(group, temp1, NULL, g1, rhoForMalSec, ctx);
        ret *=1-EC_POINT_cmp(group, temp1, g, ctx);

        EC_POINT_free(temp1);
        EC_POINT_free(t);
        EC_POINT_free(g);
        BN_free(s1);
        BN_free(s2);
        BN_free(e);


        return ret;
    }

}


//Prover first step of proof of plaintext bit
//Behaves differently depending on if x == 0 or 1, the unknown half of the ZKP is "faked"
//c is the commitment value, could be 0 or 1 depending on x
//Inputs: group, g1, g, x, c
//Outputs: c2, r2, e1, rho, rhop, t1, t2
void proofOfPlaintextBitStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, unsigned int x, EC_POINT * c,  BIGNUM * e1, BIGNUM * e2, BIGNUM * rho, BIGNUM * rhop, EC_POINT * t1, EC_POINT * t2, BN_CTX * ctx) {
    randomBNFromECGroup(group, rho, ctx);
    randomBNFromECGroup(group, rhop, ctx);

    EC_POINT * temp = EC_POINT_new(group);

    if( x == 1 ) {
        randomBNFromECGroup(group, e2, ctx);

        //Generate correct commitment for x = 1
        EC_POINT_mul(group, t1, NULL, g1, rho, ctx);

        //printf("Prover commiting with rho=");
        //BN_print_fp(stdout, rho);
        //printf("\n");

        //Multiply by the fabricated challenge
        EC_POINT_mul(group, t2, NULL, c, e2, ctx);
        //Invert
        EC_POINT_invert(group, t2, ctx);

        //Finish commitment
        EC_POINT_mul(group, temp, NULL, g1, rhop, ctx);
        EC_POINT_add(group, t2, temp, t2, ctx);
    }
    else {
        randomBNFromECGroup(group, e1, ctx);
        //Fake commitment for x = 1
        //Invert g (necessary to zero out commitment of 1)
        EC_POINT_copy(t1, g);
        EC_POINT_invert(group, t1, ctx);

        //Add g^-1 to c
        EC_POINT_add(group, t1, t1, c, ctx);

        //Calculate ^e1
        EC_POINT_mul(group, t1, NULL, t1, e1, ctx);
        //Invert (because we want -e1)
        EC_POINT_invert(group, t1, ctx);

        //Create proof commitment and add to t1
        EC_POINT_mul(group, temp, NULL, g1, rho, ctx);
        EC_POINT_add(group, t1, temp, t1, ctx);

        //Generate correct commitment for x = 0
        EC_POINT_mul(group, t2, NULL, g1, rhop, ctx);
    }

    EC_POINT_free(temp);
}

//Verifier second step of proof of plaintext bit
//Inputs: group
//Outputs: e
void proofOfPlaintextBitStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx) {
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of plaintext bit
//Inputs: group, g1, e1, e, rho, r
//Outputs: e2, s1
void proofOfPlaintextBitStep3(EC_GROUP * group, unsigned int x, BIGNUM * e1, BIGNUM * e, BIGNUM * rho, BIGNUM * rhop, BIGNUM * r, BIGNUM * e2, BIGNUM * s1, BIGNUM * s2, BN_CTX * ctx) {
    BIGNUM * order = BN_new();
    EC_GROUP_get_order(group, order, ctx);


    if( x == 1 ) {
        BN_mod_sub(e1, e, e2, order, ctx);

        BN_mod_mul(s1, e1, r, order, ctx);
        BN_mod_add(s1, s1, rho, order, ctx);

        BN_copy(s2, rhop);
    }
    else {
        BN_mod_sub(e2, e, e1, order, ctx);

        BN_mod_mul(s2, e2, r, order, ctx);
        BN_mod_add(s2, s2, rhop, order, ctx);

        BN_copy(s1, rho);
    }

    BN_free(order);
}

//Verifier fourth step of proof of plaintext bit
//Inputs: group, g1, x, c
//Returns: 1 if verifies successfully
int proofOfPlaintextBitStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, BIGNUM * e, BIGNUM * e1, BIGNUM * e2, BIGNUM * s1, BIGNUM * s2, EC_POINT * t1, EC_POINT * t2, EC_POINT * c, BN_CTX * ctx) {
    BIGNUM * temp = BN_new();
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);
    BIGNUM * order = BN_new();

    int retval = 1;

    EC_GROUP_get_order(group, order, ctx);

    BN_mod_add(temp, e1, e2, order, ctx);
    int cmp = BN_cmp(e, temp);

    if(cmp != 0) {
        printf("Cmp 1 failed\n");
        retval = 0;
    }

    EC_POINT_copy(temp1, g);
    EC_POINT_invert(group, temp1, ctx);
    EC_POINT_add(group, temp1, temp1, c, ctx);

    EC_POINT_mul(group, temp1, NULL, temp1, e1, ctx);
    EC_POINT_add(group, temp1, temp1, t1, ctx);

    EC_POINT_mul(group, temp2, NULL, g1, s1, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp2, ctx);

    if(cmp != 0) {
        printf("Cmp 2 failed\n");
        retval = 0;
    }

    EC_POINT_mul(group, temp1, NULL, c, e2, ctx);
    EC_POINT_add(group, temp1, temp1, t2, ctx);

    EC_POINT_mul(group, temp2, NULL, g1, s2, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp2, ctx);

    if(cmp != 0) {
        printf("Cmp 3 failed\n");
        retval = 0;
    }

    BN_free(temp);
    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);
    BN_free(order);

    return retval;
}


int proveCommitments(NetIO *io, SENDERSTATE * ss, int ell, BIGNUM ** comr) {
    EC_POINT ** com= (EC_POINT **) malloc(2*ell*sizeof(EC_POINT *));

    for (int i = 0; i<ell; i++) {
        com[i] = EC_POINT_new(ss->group);
        com[i+ell] = EC_POINT_new(ss->group);
        commit(ss->group, ss->g1, ss->g2, ss->a[i], com[i], comr[i], ss->ctx);
        commit(ss->group, ss->g1, ss->g2, ss->b[i], com[i+ell], comr[i+ell], ss->ctx);
        sendPoint(io, com[i], ss->group, ss->ctx);
        sendPoint(io, com[i+ell], ss->group, ss->ctx);
    }
    //Prove PT knowledge
    int ret = parallelProofOfPTKnowledge(io, ss->ctx, ss->group, ss->g1, ss->g2, PROVER, com, ss->a, comr, ell);
    ret *=parallelProofOfPTKnowledge(io, ss->ctx, ss->group, ss->g1, ss->g2, PROVER, &(com[ell]), ss->b, &(comr[ell]), ell);

    for (int i = 0; i< ell; i++) {
        EC_POINT_free(com[i]);
    }

    return ret;

}

int verifyCommitments(NetIO *io, int ell, RECEIVERSTATE * rs, EC_POINT ** com) {

    for (int i = 0; i<ell; i++) {
        //Receive commitment
        receivePoint(io, &(com[i]), rs->group, rs->ctx);
        receivePoint(io, &(com[i+ell]), rs->group, rs->ctx);
    }

    //Verify PT knowledge
    int vrf = parallelProofOfPTKnowledge(io, rs->ctx, rs->group, rs->g1, rs->g2, VERIFIER, com, NULL, NULL, ell);
    vrf *= parallelProofOfPTKnowledge(io, rs->ctx, rs->group, rs->g1, rs->g2, VERIFIER, &(com[ell]), NULL, NULL, ell);

    return vrf;

}

int proveBit(NetIO *io, int x, EC_POINT * com, BIGNUM * r, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx) {

    EC_POINT * t1 = EC_POINT_new(group);
    EC_POINT * t2 = EC_POINT_new(group);
    BIGNUM * e1 = BN_new();
    BIGNUM * e2 = BN_new();
    BIGNUM * rho = BN_new();
    BIGNUM * rhop = BN_new();
    BIGNUM * s1 = BN_new();
    BIGNUM * s2 = BN_new();
    BIGNUM * e = BN_new();

    BIGNUM * rhoForMalSec = BN_new();
    EC_POINT * g = EC_POINT_new(group);
    EC_POINT * verifierCommitment;
    ZKPoKStep1Prover(io, rhoForMalSec, &verifierCommitment, g, group, ctx, g1);

    proofOfPlaintextBitStep1(group, g1, g2, x, com, e1, e2, rho, rhop, t1, t2, ctx);

    //Send t1, t2, com sender
    sendPoint(io, t1, group, ctx);
    sendPoint(io, t2, group, ctx);
    sendPoint(io, com, group, ctx);

    //Receive challenge (e,r)
    BIGNUM * mal_r = BN_new();
    receiveBN(io, e);
    receiveBN(io, mal_r);

    if(verifyCommitment(group, g1, g, e, verifierCommitment, mal_r, ctx)!=1) {
        return 0;
    }

    proofOfPlaintextBitStep3(group, x, e1, e, rho, rhop, r, e2, s1, s2, ctx);

    //Send e1, e2, s1, s2 to sender
    sendBN(io, e1);
    sendBN(io, e2);
    sendBN(io, s1);
    sendBN(io, s2);

    //Send rhoForMalSec to complete extractability
    sendBN(io, rhoForMalSec);

    EC_POINT_free(t1);
    EC_POINT_free(g);
    EC_POINT_free(verifierCommitment);
    EC_POINT_free(t2);
    BN_free(s1);
    BN_free(mal_r);
    BN_free(s2);
    BN_free(e1);
    BN_free(e2);
    BN_free(e);
    BN_free(rho);
    BN_free(rhop);
    BN_free(rhoForMalSec);

    return 1;

}

int verifyBit(NetIO *io, EC_POINT **com, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx) {

    EC_POINT *t1;
    EC_POINT *t2;
    BIGNUM *e = BN_new();
    BIGNUM *e1 = BN_new();
    BIGNUM *e2 = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *s2 = BN_new();
    BIGNUM * mal_r = BN_new();
    EC_POINT *g;

    randomBNFromECGroup(group, e, ctx);
    ZKPoKStep1Verifier(io, &g, e, mal_r, group, ctx, g1);

    //Receive t1, t2, commitment
    receivePoint(io, &t1, group, ctx);
    receivePoint(io, &t2, group, ctx);
    receivePoint(io, com, group, ctx);

    //Send e,r to receiver
    sendBN(io, e);
    sendBN(io, mal_r);

    //Receive completed proof back
    receiveBN(io, e1);
    receiveBN(io, e2);
    receiveBN(io, s1);
    receiveBN(io, s2);

    BIGNUM * rhoForMalSec = BN_new();
    receiveBN(io, rhoForMalSec);

    int ret = proofOfPlaintextBitStep4(group, g1, g2, e, e1, e2, s1, s2, t1, t2, *com, ctx);

    //Verify rhoForMalSec
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT_mul(group, temp1, NULL, g1, rhoForMalSec, ctx);
    ret *=1-EC_POINT_cmp(group, temp1, g, ctx);

    EC_POINT_free(temp1);
    EC_POINT_free(g);
    EC_POINT_free(t1);
    EC_POINT_free(t2);
    BN_free(e);
    BN_free(e1);
    BN_free(e2);
    BN_free(s1);
    BN_free(s2);
    BN_free(mal_r);
    BN_free(rhoForMalSec);

    return ret;
}


//Verifier second step of proof of plaintext
//Inputs: group
//Outputs: e
void proofOfEncryptionStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx) {
    randomBNFromECGroup(group, e, ctx);
}

int proveEnc(NetIO *io, EC_POINT *pk, EC_POINT *epk, EC_POINT *c, BIGNUM *r_enc, BIGNUM *msg, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx) {
    //First step, normalize ciphertext
    zeroCiphertext(group, g2, c, msg, c, ctx);

    //prepare for malicious security
    BIGNUM * rhoForMalSec = BN_new();
    EC_POINT * g = EC_POINT_new(group);
    EC_POINT * verifierCommitment;
    ZKPoKStep1Prover(io, rhoForMalSec, &verifierCommitment, g, group, ctx, g1);

    //Prover step 1, generate rho, t1 and t2
    BIGNUM * rho = BN_new();
    EC_POINT * t1 = EC_POINT_new(group);
    EC_POINT * t2 = EC_POINT_new(group);

    proofOfEncryptionStep1(group, g1, epk, pk, c, t1, t2, rho, ctx);

    //Send t1,t2
    sendPoint(io, t1, group, ctx);
    sendPoint(io, t2, group, ctx);

    //Receive challenge (e,r)
    BIGNUM * mal_r = BN_new();
    BIGNUM * e = BN_new();
    receiveBN(io, e);
    receiveBN(io, mal_r);

    //Verify challenge vs. verifier's commitment
    if(verifyCommitment(group, g1, g, e, verifierCommitment, mal_r, ctx)!=1) {
        return 0;
    }

    //Prover step 3, generate s, send s
    BIGNUM * s = BN_new();
    proofOfEncryptionStep3(group, e, rho, r_enc, s, ctx);

    sendBN(io, s);

    //Send rhoForMalSec to complete extractability
    sendBN(io, rhoForMalSec);

    BN_free(rho);
    BN_free(s);
    BN_free(e);
    BN_free(mal_r);
    BN_free(rhoForMalSec);
    EC_POINT_free(t1);
    EC_POINT_free(g);
    EC_POINT_free(verifierCommitment);
    EC_POINT_free(t2);

    return 1;
}

int verifyEnc(NetIO *io, EC_POINT *pk, EC_POINT *epk, EC_POINT *c, BIGNUM *msg, EC_GROUP * group, EC_POINT * g1, EC_POINT * g2, BN_CTX * ctx) {
    //First step, normalize ciphertext
    zeroCiphertext(group, g2, c, msg, c, ctx);

    //Commit to random challenge e
    BIGNUM * e = BN_new();
    BIGNUM * mal_r = BN_new();
    EC_POINT *g;

    randomBNFromECGroup(group, e, ctx);
    ZKPoKStep1Verifier(io, &g, e, mal_r, group, ctx, g1);

    EC_POINT *t1;
    EC_POINT *t2;

    //Receive t1, t2
    receivePoint(io, &t1, group, ctx);
    receivePoint(io, &t2, group, ctx);

    //Verifier step 2, reveal challenge (e,r)
    sendBN(io, e);
    sendBN(io, mal_r);

    //Receive s
    BIGNUM * s = BN_new();
    receiveBN(io, s);

    BIGNUM * rhoForMalSec = BN_new();
    receiveBN(io, rhoForMalSec);

    int ret = proofOfEncryptionStep4(group, g1, epk, pk, c, s, e, t1, t2, ctx);

    //Verify rhoForMalSec
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT_mul(group, temp1, NULL, g1, rhoForMalSec, ctx);
    ret *=1-EC_POINT_cmp(group, temp1, g, ctx);

    EC_POINT_free(temp1);


    BN_free(rhoForMalSec);
    BN_free(s);
    BN_free(e);
    BN_free(mal_r);
    EC_POINT_free(t1);
    EC_POINT_free(t2);
    EC_POINT_free(g);
    return ret;
}

//Prover first step of proof of shuffle
//Inputs: group, g1, g2, pk, A, B
//Outputs: t1, t2, t3, rho1, rho2, rho3
void proofOfShuffleStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * pk, EC_POINT * A, EC_POINT * B, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * rho3, BN_CTX * ctx) {
    EC_POINT * temp = EC_POINT_new(group);

    randomBNFromECGroup(group, rho1, ctx);
    randomBNFromECGroup(group, rho2, ctx);
    randomBNFromECGroup(group, rho3, ctx);

    //t1 = g^rho1 * A^rho2
    EC_POINT_mul(group, t1, NULL, g1, rho1, ctx);
    EC_POINT_mul(group, temp, NULL, A, rho2, ctx);
    EC_POINT_add(group, t1, temp, t1, ctx);

    //t2 = pk^rho1 * B^rho2
    EC_POINT_mul(group, t2, NULL, pk, rho1, ctx);
    EC_POINT_mul(group, temp, NULL, B, rho2, ctx);
    EC_POINT_add(group, t2, t2, temp, ctx);

    //t3 = g1^rho3 * g^rho2
    EC_POINT_mul(group, t3, NULL, g1, rho3, ctx);
    EC_POINT_mul(group, temp, NULL, g, rho2, ctx);
    EC_POINT_add(group, t3, temp, t3, ctx);

    EC_POINT_free(temp);
}

//Verifier second step of proof of shuffle
//Inputs: group
//Outputs: e
void proofOfShuffleStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx) {
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of shuffle
//Inputs: group, rho1, rho2, rho3, e, x, r, rprime
//Outputs: s1, s2, s3
void proofOfShuffleStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * rho3, BIGNUM * e, BIGNUM *x, BIGNUM * r, BIGNUM * rprime, BIGNUM * s1, BIGNUM * s2, BIGNUM * s3, BN_CTX * ctx) {
    BIGNUM * temp = BN_new();
    BIGNUM * order = BN_new();

    EC_GROUP_get_order(group, order, ctx);

    //s1 = rho1 + e * rprime
    BN_mod_mul(temp, e, rprime, order, ctx);
    BN_mod_add(s1, rho1, temp, order, ctx);

    //s2 = rho2 + e*x
    /*    BN_zero(temp);
    if(x != 0) {
        BN_copy(temp, e);
    }
    BN_mod_add(s2, rho2, temp, order, ctx);
    */
    BN_mod_mul(temp, e, x, order, ctx);
    BN_mod_add(s2, rho2, temp, order, ctx);

    //s3 = rho3 + e * r
    BN_mod_mul(temp, e, r, order, ctx);
    BN_mod_add(s3, rho3, temp, order, ctx);

    BN_free(order);
    BN_free(temp);
}

//Verifier fourth step of proof of shuffle
//Inputs: group, g1, g, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com
//Returns: 1 if verifies successfully
int proofOfShuffleStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * pk, EC_POINT * A, EC_POINT * B, EC_POINT * C, EC_POINT * D, BIGNUM * s1, BIGNUM * s2, BIGNUM * s3, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * e, EC_POINT * com, BN_CTX * ctx) {
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);

    int ret = 1;

    //Check if g1^s2 * A^s2 = C^e * t1
    EC_POINT_mul(group, temp1, NULL, A, s2, ctx);
    EC_POINT_mul(group, temp2, NULL, g1, s1, ctx);
    EC_POINT_add(group, temp1, temp1, temp2, ctx);

    EC_POINT_mul(group, temp3, NULL, C, e, ctx);
    EC_POINT_add(group, temp3, temp3, t1, ctx);

    int cmp = EC_POINT_cmp(group, temp1, temp3, ctx);
    if( cmp != 0 ) {
        printf("Failed cmp 1\n");
        ret = 0;
    }

    //Check if pk^s1 * B^s2 = D ^ e * t2
    EC_POINT_mul(group, temp1, NULL, pk, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, B, s2, ctx);
    EC_POINT_add(group,temp1, temp1, temp2, ctx);

    EC_POINT_mul(group, temp3, NULL, D, e, ctx);
    EC_POINT_add(group, temp3, temp3, t2, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp3, ctx);
    if( cmp != 0 ) {
        printf("Failed cmp 2\n");
        ret = 0;
    }

    //Check if g1^s3 * g^s2 = com^e * t3
    EC_POINT_mul(group, temp1, NULL, g1, s3, ctx);
    EC_POINT_mul(group, temp2, NULL, g, s2, ctx);
    EC_POINT_add(group,temp1, temp1, temp2, ctx);

    EC_POINT_mul(group, temp3, NULL, com, e, ctx);
    EC_POINT_add(group, temp3, temp3, t3, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp3, ctx);
    if( cmp != 0 ) {
        printf("Failed cmp 3\n");
        ret = 0;
    }

    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);

    return ret;
}


int proveShuffle(NetIO *io, EC_POINT *pk, BIGNUM * x, BIGNUM *one_minus_x, BIGNUM *r_com_x_i, BIGNUM *r_com_one_minus_x_i, BIGNUM **randomize_r, EC_POINT * V0, EC_POINT * V1, EC_POINT * D0, EC_POINT * D1, EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx) {
    EC_POINT **vt = (EC_POINT **) malloc(3*sizeof(EC_POINT *));
    EC_POINT **vpt = (EC_POINT **) malloc(3*sizeof(EC_POINT *));
    EC_POINT **dt = (EC_POINT **) malloc(3*sizeof(EC_POINT *));
    EC_POINT **dpt = (EC_POINT **) malloc(3*sizeof(EC_POINT *));
    BIGNUM **vrho = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **vprho = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **drho = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **dprho = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **vs = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **vps = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **ds = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **dps = (BIGNUM **) malloc(3*sizeof(BIGNUM *));


    //prepare for malicious security
    BIGNUM * rhoForMalSec = BN_new();
    EC_POINT * g = EC_POINT_new(group);
    EC_POINT * verifierCommitment;
    ZKPoKStep1Prover(io, rhoForMalSec, &verifierCommitment, g, group, ctx, g1);

    //Initialize data
    for (int i = 0; i<3; i++) {
        vt[i] = EC_POINT_new(group);
        vpt[i] = EC_POINT_new(group);
        dt[i] = EC_POINT_new(group);
        dpt[i] = EC_POINT_new(group);

        vrho[i] = BN_new();
        vprho[i] = BN_new();
        drho[i] = BN_new();
        dprho[i] = BN_new();

        vs[i] = BN_new();
        vps[i] = BN_new();
        ds[i] = BN_new();
        dps[i] = BN_new();

    }

    //Generate rhos and ts
    proofOfShuffleStep1(group, g1, g2, pk, V0, V1, vt[0], vt[1], vt[2], vrho[0], vrho[1], vrho[2], ctx);
    proofOfShuffleStep1(group, g1, g2, pk, V0, V1, vpt[0], vpt[1], vpt[2], vprho[0], vprho[1], vprho[2], ctx);
    proofOfShuffleStep1(group, g1, g2, pk, D0, D1, dt[0], dt[1], dt[2], drho[0], drho[1], drho[2], ctx);
    proofOfShuffleStep1(group, g1, g2, pk, D0, D1, dpt[0], dpt[1], dpt[2], dprho[0], dprho[1], dprho[2], ctx);


    //Send ts to verifier
    for (int i = 0; i<3; i++) {
        sendPoint(io, vt[i], group, ctx);
        sendPoint(io, vpt[i], group, ctx);
        sendPoint(io, dt[i], group, ctx);
        sendPoint(io, dpt[i], group, ctx);
    }

    //Receive verifier's challenge (e,r)
    BIGNUM *e = BN_new();
    BIGNUM * mal_r = BN_new();
    receiveBN(io, e);
    receiveBN(io, mal_r);

    //Verify challenge vs. verifier's commitment
    if(verifyCommitment(group, g1, g, e, verifierCommitment, mal_r, ctx)!=1) {
        return 0;
    }

    //Prover step 3, generate s and send
    proofOfShuffleStep3(group, vrho[0], vrho[1], vrho[2], e, x, r_com_x_i, randomize_r[0], vs[0], vs[1], vs[2], ctx);
    proofOfShuffleStep3(group, vprho[0], vprho[1], vprho[2], e, one_minus_x, r_com_one_minus_x_i, randomize_r[1], vps[0], vps[1], vps[2], ctx);
    proofOfShuffleStep3(group, drho[0], drho[1], drho[2], e, x, r_com_x_i, randomize_r[2], ds[0], ds[1], ds[2], ctx);
    proofOfShuffleStep3(group, dprho[0], dprho[1], dprho[2], e, one_minus_x, r_com_one_minus_x_i, randomize_r[3], dps[0], dps[1], dps[2], ctx);


    for (int i = 0; i<3; i++) {
        sendBN(io, vs[i]);
        sendBN(io, vps[i]);
        sendBN(io, ds[i]);
        sendBN(io, dps[i]);
    }

    //Send rhoForMalSec to complete extractability
    sendBN(io, rhoForMalSec);


    //Done, clean up memory
    for (int i = 0; i<3; i++) {
        EC_POINT_free(vt[i]);
        EC_POINT_free(vpt[i]);
        EC_POINT_free(dt[i]);
        EC_POINT_free(dpt[i]);

        BN_free(vrho[i]);
        BN_free(vprho[i]);
        BN_free(drho[i]);
        BN_free(dprho[i]);

        BN_free(vs[i]);
        BN_free(vps[i]);
        BN_free(ds[i]);
        BN_free(dps[i]);
    }

    BN_free(rhoForMalSec);
    BN_free(mal_r);
    BN_free(e);
    EC_POINT_free(g);
    EC_POINT_free(verifierCommitment);

    free(vs);
    free(vps);
    free(ds);
    free(dps);
    free(vt);
    free(vpt);
    free(dt);
    free(dpt);
    free(vrho);
    free(vprho);
    free(drho);
    free(dprho);

    return 1;
}

int verifyShuffle(NetIO *io, EC_POINT *pk, EC_POINT *V0, EC_POINT *V1, EC_POINT *D0, EC_POINT *D1, EC_POINT *c0, EC_POINT *c1, EC_POINT *cp0, EC_POINT *cp1, EC_POINT *d0, EC_POINT *d1,EC_POINT *dp0, EC_POINT *dp1, EC_POINT *com_x, EC_POINT *com_one_minus_x,  EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx) {
    EC_POINT **vt = (EC_POINT **) malloc(3*sizeof(EC_POINT*));
    EC_POINT **vpt = (EC_POINT **) malloc(3*sizeof(EC_POINT*));
    EC_POINT **dt = (EC_POINT **) malloc(3*sizeof(EC_POINT*));
    EC_POINT **dpt = (EC_POINT **) malloc(3*sizeof(EC_POINT*));
    BIGNUM **vs = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **vps = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **ds = (BIGNUM **) malloc(3*sizeof(BIGNUM *));
    BIGNUM **dps = (BIGNUM **) malloc(3*sizeof(BIGNUM *));

    //Initialize memory
    for (int i = 0; i<3; i++) {
        vs[i] = BN_new();
        vps[i] = BN_new();
        ds[i] = BN_new();
        dps[i] = BN_new();
    }

    //Commit to random challenge e and send commitment
    BIGNUM * e = BN_new();
    BIGNUM * mal_r = BN_new();
    EC_POINT *g;

    randomBNFromECGroup(group, e, ctx);
    ZKPoKStep1Verifier(io, &g, e, mal_r, group, ctx, g1);


    //Receive ts from prover
    for (int i = 0; i<3; i++) {
        vs[i] = BN_new();
        vps[i] = BN_new();
        ds[i] = BN_new();
        dps[i] = BN_new();

        receivePoint(io, &(vt[i]), group, ctx);
        receivePoint(io, &(vpt[i]), group, ctx);
        receivePoint(io, &(dt[i]), group, ctx);
        receivePoint(io, &(dpt[i]), group, ctx);
    }

    //Send (e,r) to receiver
    sendBN(io, e);
    sendBN(io, mal_r);

    for (int i = 0; i<3; i++) {
        receiveBN(io, vs[i]);
        receiveBN(io, vps[i]);
        receiveBN(io, ds[i]);
        receiveBN(io, dps[i]);
    }

    //Receive rho to check generator
    BIGNUM * rhoForMalSec = BN_new();
    receiveBN(io, rhoForMalSec);

    //Verify rhoForMalSec
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT_mul(group, temp1, NULL, g1, rhoForMalSec, ctx);
    int ret =1-EC_POINT_cmp(group, temp1, g, ctx);

    EC_POINT_free(temp1);

    ret *= proofOfShuffleStep4(group, g1, g2, pk, V0, V1, c0, c1, vs[0], vs[1], vs[2], vt[0], vt[1], vt[2], e, com_x, ctx);

    ret *= proofOfShuffleStep4(group, g1, g2, pk, V0, V1, cp0, cp1, vps[0], vps[1], vps[2], vpt[0], vpt[1], vpt[2], e, com_one_minus_x, ctx);

    ret *= proofOfShuffleStep4(group, g1, g2, pk, D0, D1, d0, d1, ds[0], ds[1], ds[2], dt[0], dt[1], dt[2], e, com_x, ctx);

    ret *= proofOfShuffleStep4(group, g1, g2, pk, D0, D1, dp0, dp1, dps[0], dps[1], dps[2], dpt[0], dpt[1], dpt[2], e, com_one_minus_x, ctx);


    //Done, clean up memory
    for (int i = 0; i<3; i++) {
        EC_POINT_free(vt[i]);
        EC_POINT_free(vpt[i]);
        EC_POINT_free(dt[i]);
        EC_POINT_free(dpt[i]);

        BN_free(vs[i]);
        BN_free(vps[i]);
        BN_free(ds[i]);
        BN_free(dps[i]);
    }

    BN_free(e);
    BN_free(mal_r);
    BN_free(rhoForMalSec);
    EC_POINT_free(g);

    free(vs);
    free(vps);
    free(ds);
    free(dps);

    free(vt);
    free(vpt);
    free(dt);
    free(dpt);

    return ret;

}

//Prover first step of proof of shuffle
//Inputs: group, g1, g2, A, B
//Outputs: t1, t2, t3, rho1, rho2
void proofOfMultiplicationStep1(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * A, EC_POINT * B, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * rho1, BIGNUM * rho2, BN_CTX * ctx) {
    EC_POINT * temp = EC_POINT_new(group);

    randomBNFromECGroup(group, rho1, ctx);
    randomBNFromECGroup(group, rho2, ctx);

    //t1 = A^rho1
    EC_POINT_mul(group, t1, NULL, A, rho1, ctx);

    //t2 = B^rho2
    EC_POINT_mul(group, t2, NULL, B, rho1, ctx);

    //t3 = g1^rho2 * g^rho1
    EC_POINT_mul(group, temp, NULL, g, rho1, ctx);
    EC_POINT_mul(group, t3, NULL, g1, rho2, ctx);
    EC_POINT_add(group, t3, t3, temp, ctx);


    EC_POINT_free(temp);
}

//Verifier second step of proof of shuffle
//Inputs: group
//Outputs: e
void proofOfMultiplicationStep2(EC_GROUP * group, BIGNUM * e, BN_CTX * ctx) {
    randomBNFromECGroup(group, e, ctx);
}

//Prover third step of proof of shuffle
//Inputs: group, rho1, rho2, e, x, r
//Outputs: s1, s2
void proofOfMultiplicationStep3(EC_GROUP * group, BIGNUM * rho1, BIGNUM * rho2, BIGNUM * e, BIGNUM * x, BIGNUM * r, BIGNUM * s1, BIGNUM * s2, BN_CTX * ctx) {

    BIGNUM * order = BN_new();

    EC_GROUP_get_order(group, order, ctx);

    BN_mod_mul(s1, e, x, order, ctx);
    BN_mod_add(s1, rho1, s1, order, ctx);

    BN_mod_mul(s2, e, r, order, ctx);
    BN_mod_add(s2, s2, rho2, order, ctx);

    BN_free(order);
}

//Verifier fourth step of proof of shuffle
//Inputs: group, g1, g, pk, A, B, C, D, s1, s2, s3, t1, t2, t3, e, com
//Returns: 1 if verifies successfully
int proofOfMultiplicationStep4(EC_GROUP * group, EC_POINT * g1, EC_POINT * g, EC_POINT * A, EC_POINT * B, EC_POINT * C, EC_POINT * D, BIGNUM * s1, BIGNUM * s2, EC_POINT * t1, EC_POINT * t2, EC_POINT * t3, BIGNUM * e, EC_POINT * com, BN_CTX * ctx) {
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT * temp2 = EC_POINT_new(group);
    EC_POINT * temp3 = EC_POINT_new(group);

    int ret = 1;

    //Check if A^s1 = C^e * t1

    EC_POINT_mul(group, temp1, NULL, A, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, C, e, ctx);
    EC_POINT_add(group, temp2, temp2, t1, ctx);

    int cmp = EC_POINT_cmp(group, temp1, temp2, ctx);

    if( cmp != 0 ) {
        ret = 0;
        printf("Failed cmp 1\n");
    }

    //Check if B^s1 = D^e * t2

    EC_POINT_mul(group, temp1, NULL, B, s1, ctx);
    EC_POINT_mul(group, temp2, NULL, D, e, ctx);
    EC_POINT_add(group, temp2, temp2, t2, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp2, ctx);

    if( cmp != 0 ) {
        ret = 0;
        printf("Failed cmp 2\n");
    }

    //Check if g_1^s2 * g^s1 = com^e * t3
    EC_POINT_mul(group, temp1, NULL, g1, s2, ctx);
    EC_POINT_mul(group, temp2, NULL, g, s1, ctx);
    EC_POINT_add(group, temp1, temp1, temp2, ctx);

    EC_POINT_mul(group, temp3, NULL, com, e, ctx);
    EC_POINT_add(group, temp3, temp3, t3, ctx);

    cmp = EC_POINT_cmp(group, temp1, temp3, ctx);

    if( cmp != 0 ) {
        ret = 0;
        printf("Failed cmp 3\n");
    }

    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    EC_POINT_free(temp3);

    return ret;
}

int proveMul(NetIO *io,  EC_POINT *A,  EC_POINT *B, BIGNUM *factor, BIGNUM *com_r, EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx) {
    BIGNUM *e = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *s2 = BN_new();
    BIGNUM *rho1 = BN_new();
    BIGNUM *rho2 = BN_new();
    EC_POINT *t1 = EC_POINT_new(group);
    EC_POINT *t2 = EC_POINT_new(group);
    EC_POINT *t3 = EC_POINT_new(group);

    //prepare for malicious security
    BIGNUM * rhoForMalSec = BN_new();
    EC_POINT * g = EC_POINT_new(group);
    EC_POINT * verifierCommitment;
    ZKPoKStep1Prover(io, rhoForMalSec, &verifierCommitment, g, group, ctx, g1);

    //Generate ts and send them
    proofOfMultiplicationStep1(group, g1, g2, A, B, t1, t2, t3, rho1, rho2, ctx);
    sendPoint(io, t1, group, ctx);
    sendPoint(io, t2, group, ctx);
    sendPoint(io, t3, group, ctx);

    //Receive verifier's challenge (e,r)
    BIGNUM * mal_r = BN_new();
    receiveBN(io, e);
    receiveBN(io, mal_r);

    //Verify challenge vs. verifier's commitment
    if(verifyCommitment(group, g1, g, e, verifierCommitment, mal_r, ctx)!=1) {
        return 0;
    }


    //Generate and send s1, s2
    proofOfMultiplicationStep3(group, rho1, rho2, e, factor, com_r, s1, s2, ctx);
    sendBN(io, s1);
    sendBN(io, s2);


    //Send rhoForMalSec to complete extractability
    sendBN(io, rhoForMalSec);


    //Done, free memory
    EC_POINT_free(g);
    EC_POINT_free(verifierCommitment);
    EC_POINT_free(t1);
    EC_POINT_free(t2);
    EC_POINT_free(t3);
    BN_free(e);
    BN_free(s1);
    BN_free(s2);
    BN_free(rho1);
    BN_free(rho2);
    BN_free(rhoForMalSec);
    BN_free(mal_r);
    return 1;
}

int verifyMul(NetIO *io, EC_POINT *A, EC_POINT *B, EC_POINT *C, EC_POINT *D, EC_POINT *com, EC_POINT *g1, EC_POINT *g2, EC_GROUP * group, BN_CTX * ctx) {

    EC_POINT *t1, *t2, *t3;
    BIGNUM *s1 = BN_new();
    BIGNUM *s2 = BN_new();

    //Commit to random challenge e and send commitment
    BIGNUM * e = BN_new();
    BIGNUM * mal_r = BN_new();
    EC_POINT *g;

    randomBNFromECGroup(group, e, ctx);
    ZKPoKStep1Verifier(io, &g, e, mal_r, group, ctx, g1);


    receivePoint(io, &t1, group, ctx);
    receivePoint(io, &t2, group, ctx);
    receivePoint(io, &t3, group, ctx);

    //Send challenge (e,r)
    sendBN(io, e);
    sendBN(io, mal_r);

    //Receive s1, s2
    receiveBN(io, s1);
    receiveBN(io, s2);

    //Receive rho to check generator
    BIGNUM * rhoForMalSec = BN_new();
    receiveBN(io, rhoForMalSec);

    //Verify rhoForMalSec
    EC_POINT * temp1 = EC_POINT_new(group);
    EC_POINT_mul(group, temp1, NULL, g1, rhoForMalSec, ctx);
    int ret =1-EC_POINT_cmp(group, temp1, g, ctx);

    EC_POINT_free(temp1);


    ret *= proofOfMultiplicationStep4(group, g1, g2, A, B, C, D, s1, s2, t1, t2, t3, e, com, ctx);


    //Done, free memory
    EC_POINT_free(g);
    EC_POINT_free(t1);
    EC_POINT_free(t2);
    EC_POINT_free(t3);
    BN_free(e);
    BN_free(s1);
    BN_free(s2);
    BN_free(mal_r);
    BN_free(rhoForMalSec);

    return ret;

}

int proveReX(NetIO *io, SENDERSTATE *ss, EC_POINT *receiver_pk, BIGNUM *alpha_beta_i, BIGNUM *com_r_alpha_beta, BIGNUM *r_renc, BIGNUM *alpha_beta_ip, BIGNUM *com_r_alpha_betap, BIGNUM *r_rencp) {

    BIGNUM *myrho0 = BN_new();
    BIGNUM *myrho1 = BN_new();
    BIGNUM *myrho2 = BN_new();
    EC_POINT *myt0 = EC_POINT_new (ss->group);
    EC_POINT *myt1 = EC_POINT_new (ss->group);
    EC_POINT *myt2 = EC_POINT_new (ss->group);
    BIGNUM *myrho0p = BN_new();
    BIGNUM *myrho1p = BN_new();
    BIGNUM *myrho2p = BN_new();
    EC_POINT *myt0p = EC_POINT_new (ss->group);
    EC_POINT *myt1p = EC_POINT_new (ss->group);
    EC_POINT *myt2p = EC_POINT_new (ss->group);

    //prepare for malicious security
    BIGNUM * rhoForMalSec = BN_new();
    EC_POINT * g = EC_POINT_new(ss->group);
    EC_POINT * verifierCommitment;
    ZKPoKStep1Prover(io, rhoForMalSec, &verifierCommitment, g, ss->group, ss->ctx, ss->g1);

    proofOfShuffleStep1(ss->group, ss->g1, ss->g2, receiver_pk, ss->T0, ss->T1, myt0, myt1, myt2, myrho0, myrho1, myrho2, ss->ctx);

    proofOfShuffleStep1(ss->group, ss->g1, ss->g2, receiver_pk, ss->U0, ss->U1, myt0p, myt1p, myt2p, myrho0p, myrho1p, myrho2p, ss->ctx);


    sendPoint(io, myt0, ss->group, ss->ctx);
    sendPoint(io, myt1, ss->group, ss->ctx);
    sendPoint(io, myt2, ss->group, ss->ctx);

    sendPoint(io, myt0p, ss->group, ss->ctx);
    sendPoint(io, myt1p, ss->group, ss->ctx);
    sendPoint(io, myt2p, ss->group, ss->ctx);


    //Receive verifier's challenge (e,r)
    BIGNUM *mye = BN_new();
    BIGNUM * mal_r = BN_new();
    receiveBN(io, mye);
    receiveBN(io, mal_r);

    //Verify challenge vs. verifier's commitment
    if(verifyCommitment(ss->group, ss->g1, g, mye, verifierCommitment, mal_r, ss->ctx)!=1) {
        return 0;
    }

    BIGNUM *mys0 = BN_new();
    BIGNUM *mys1 = BN_new();
    BIGNUM *mys2 = BN_new();
    BIGNUM *mys0p = BN_new();
    BIGNUM *mys1p = BN_new();
    BIGNUM *mys2p = BN_new();


    proofOfShuffleStep3(ss->group, myrho0, myrho1, myrho2, mye, alpha_beta_i, com_r_alpha_beta, r_renc, mys0, mys1, mys2, ss->ctx);

    proofOfShuffleStep3(ss->group, myrho0p, myrho1p, myrho2p, mye, alpha_beta_ip, com_r_alpha_betap, r_rencp, mys0p, mys1p, mys2p, ss->ctx);


    sendBN(io, mys0);
    sendBN(io, mys1);
    sendBN(io, mys2);
    sendBN(io, mys0p);
    sendBN(io, mys1p);
    sendBN(io, mys2p);


    //Send rhoForMalSec to complete extractability
    sendBN(io, rhoForMalSec);


    BN_free(mys0);
    BN_free(mys1);
    BN_free(mys2);
    BN_free(mys0p);
    BN_free(mys1p);
    BN_free(mys2p);

    BN_free(mye);

    BN_free(myrho0);
    BN_free(myrho1);
    BN_free(myrho2);
    BN_free(myrho0p);
    BN_free(myrho1p);
    BN_free(myrho2p);

    EC_POINT_free(myt0);
    EC_POINT_free(myt1);
    EC_POINT_free(myt2);
    EC_POINT_free(myt0p);
    EC_POINT_free(myt1p);
    EC_POINT_free(myt2p);


    BN_free(rhoForMalSec);
    EC_POINT_free(g);
    EC_POINT_free(verifierCommitment);
    BN_free(mal_r);
    return 1;
}

int verifyReX(NetIO *io, RECEIVERSTATE *rs, EC_POINT *com_alpha_beta, EC_POINT *com_alpha_betap) {

    //Commit to random challenge e and send commitment
    BIGNUM * mye = BN_new();
    BIGNUM * mal_r = BN_new();
    EC_POINT *g;
    randomBNFromECGroup(rs->group, mye, rs->ctx);
    ZKPoKStep1Verifier(io, &g, mye, mal_r, rs->group, rs->ctx, rs->g1);


    EC_POINT *myt0;
    EC_POINT *myt1;
    EC_POINT *myt2;
    EC_POINT *myt0p;
    EC_POINT *myt1p;
    EC_POINT *myt2p;

    receivePoint(io, &myt0, rs->group, rs->ctx);
    receivePoint(io, &myt1, rs->group, rs->ctx);
    receivePoint(io, &myt2, rs->group, rs->ctx);
    receivePoint(io, &myt0p, rs->group, rs->ctx);
    receivePoint(io, &myt1p, rs->group, rs->ctx);
    receivePoint(io, &myt2p, rs->group, rs->ctx);


    //Send challenge (e,r)
    sendBN(io, mye);
    sendBN(io, mal_r);


    BIGNUM *mys0 = BN_new();
    BIGNUM *mys1 = BN_new();
    BIGNUM *mys2 = BN_new();
    BIGNUM *mys0p = BN_new();
    BIGNUM *mys1p = BN_new();
    BIGNUM *mys2p = BN_new();


    receiveBN(io, mys0);
    receiveBN(io, mys1);
    receiveBN(io, mys2);

    receiveBN(io, mys0p);
    receiveBN(io, mys1p);
    receiveBN(io, mys2p);


    //Receive rho to check generator
    BIGNUM * rhoForMalSec = BN_new();
    receiveBN(io, rhoForMalSec);

    //Verify rhoForMalSec
    EC_POINT * temp1 = EC_POINT_new(rs->group);
    EC_POINT_mul(rs->group, temp1, NULL, rs->g1, rhoForMalSec, rs->ctx);
    int ret =1-EC_POINT_cmp(rs->group, temp1, g, rs->ctx);

    EC_POINT_free(temp1);


    ret *=  proofOfShuffleStep4(rs->group, rs->g1, rs->g2, rs->pk, rs->T0, rs->T1, rs->X0, rs->X1, mys0, mys1, mys2, myt0, myt1, myt2, mye, com_alpha_beta, rs->ctx);

    ret *=  proofOfShuffleStep4(rs->group, rs->g1, rs->g2, rs->pk, rs->U0, rs->U1, rs->Y0, rs->Y1, mys0p, mys1p, mys2p, myt0p, myt1p, myt2p, mye, com_alpha_betap, rs->ctx);



    //Done, free memory
    BN_free(mys0);
    BN_free(mys1);
    BN_free(mys2);
    BN_free(mys0p);
    BN_free(mys1p);
    BN_free(mys2p);


    BN_free(rhoForMalSec);

    EC_POINT_free (myt0);
    EC_POINT_free(myt1);
    EC_POINT_free(myt2);
    EC_POINT_free (myt0p);
    EC_POINT_free(myt1p);
    EC_POINT_free(myt2p);


    BN_free(mye);
    BN_free(mal_r);
    EC_POINT_free(g);
    return ret;
}
