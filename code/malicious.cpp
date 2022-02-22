#include <stdio.h>

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <string.h>

#include "emp-tool/emp-tool.h"
#include <iostream>

#include "zkp.h"


using namespace std;
using namespace emp;


double cpu_time_from(std::clock_t c_start) {

   std::clock_t c_end = std::clock();
   return 1000*(c_end - c_start) / CLOCKS_PER_SEC;
  
}

int ioprf(char * input, int ell, NetIO * io, int party, int runs) {


    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP * group;

    EC_POINT * g1;
    EC_POINT * g2;

    if (readParameterFile(&group, &g1, &g2, ctx)==-1) {
        printf("Could not load parameter file.\n");
        return -1;
    }


    printf("Testing PRF of length %d, %d runs\n", ell,runs);

    RECEIVERSTATE * rs;
    SENDERSTATE * ss;

    double total_time = 0.0;
    double cpu_total_time = 0.0;
    
    for(int z = 0; z < runs; z++)
    {
        if (party==RECEIVER) {
            int *x, *one_minus_x;
            x = (int *) malloc(sizeof(int) * ell);
            one_minus_x = (int *) malloc(sizeof(int) * ell);

            for(int i = 0; i < ell; i++) {
                x[i] = input[i] == '1' ? 1 : 0;
                one_minus_x[i] = 1 - x[i];
            }

            rs = initializeReceiver(group, g1, g2);
            auto start = clock_start();
            std::clock_t cpu_start = std::clock();


            // Prove that V encrypts a 1, D encrypts a 0
            //Send V=(V0, V1), D=(D0, D1)
            sendPoint(io, rs->pk, group, ctx);
            sendPoint(io, rs->V0, group, ctx);
            sendPoint(io, rs->V1, group, ctx);
            sendPoint(io, rs->D0, group, ctx);
            sendPoint(io, rs->D1, group, ctx);

            if (proveEnc(io, rs->pk, rs->V0, rs->V1, rs->r_enc_V, rs->one, rs->group, rs->g1, rs->g2, rs->ctx)!=1) {
                cout <<"Malicious security for V failure"<<endl;
                exit(1);
            }

            if (proveEnc(io, rs->pk, rs->D0, rs->D1, rs->r_enc_D, rs->zero, rs->group, rs->g1, rs->g2, rs->ctx)!=1) {
                cout <<"Malicious security for D failure"<<endl;
                exit(1);
            }

            //Verify that sender knows alphas and betas
            EC_POINT ** com_alpha_beta = (EC_POINT **) malloc(2*ell*sizeof(EC_POINT **));

            if (verifyCommitments(io, ell, rs, com_alpha_beta)!=1) {
                cout <<"Commitment verification failure"<<endl;
                exit(1);
            }
            total_time +=time_from(start);
	    cpu_total_time +=cpu_time_from(cpu_start);
	    
            //Run ell rounds
            for( int y = 0; y < ell; y++) {

                start = clock_start();
		std::clock_t cpu_start = std::clock();

                //Prove that x_i is a bit
                //Commit to x[y]
                BIGNUM * msg = BN_new();
                EC_POINT * com_x_i = EC_POINT_new(group);
                BIGNUM * r_com_x_i = BN_new();
                bnFromInt(x[y], msg);
                commit(group, g1, g2, msg, com_x_i, r_com_x_i, ctx);

                if(proveBit(io, x[y], com_x_i, r_com_x_i, rs->group, rs->g1, rs->g2, rs->ctx)!=1) {
                    cout <<"proveBit x malicious security failed"<<endl;
                    exit(1);
                }

                //Prove that 1-x_i is a bit
                EC_POINT * com_one_minus_x_i = EC_POINT_new(group);
                BIGNUM * r_com_one_minus_x_i = BN_new();
                bnFromInt(one_minus_x[y], msg);
                commit(group, g1, g2, msg, com_one_minus_x_i, r_com_one_minus_x_i, ctx);
                BN_free(msg);

                if(proveBit(io, one_minus_x[y], com_one_minus_x_i, r_com_one_minus_x_i, rs->group, rs->g1, rs->g2, rs->ctx)!=1) {
                    cout <<"proveBit 1-x malicious security failed"<<endl;
                    exit(1);
                }

                //Prove that (x_i + 1 - x_i) is a bit
                EC_POINT * com_sum = EC_POINT_new(group);
                BIGNUM * r_sum = BN_new();
                BN_add(r_sum, r_com_x_i, r_com_one_minus_x_i);
                EC_POINT_add(rs->group, com_sum, com_x_i, com_one_minus_x_i, ctx);
                if(proveBit(io, (x[y]+one_minus_x[y]), com_sum, r_sum, rs->group, rs->g1, rs->g2, rs->ctx)!=1) {
                    cout <<"proveBit sum malicious security failed"<<endl;
                    exit(1);
                }
                BN_free(r_sum);

                receiverStep1(x[y], rs);

                sendPoint(io, rs->c0, rs->group, rs->ctx);
                sendPoint(io, rs->c1, rs->group, rs->ctx);
                sendPoint(io, rs->cp0, rs->group, rs->ctx);
                sendPoint(io, rs->cp1, rs->group, rs->ctx);
                sendPoint(io, rs->d0, rs->group, rs->ctx);
                sendPoint(io, rs->d1, rs->group, rs->ctx);
                sendPoint(io, rs->dp0, rs->group, rs->ctx);
                sendPoint(io, rs->dp1, rs->group, rs->ctx);

                BIGNUM *bX = BN_new();
                BIGNUM *bOMX= BN_new();
                bnFromInt(x[y], bX);
                bnFromInt(1-x[y], bOMX);
                if (proveShuffle(io, rs->pk, bX, bOMX, r_com_x_i, r_com_one_minus_x_i, rs->randomize_r, rs->V0, rs->V1, rs->D0, rs->D1, rs->g1, rs->g2, rs->group, rs->ctx)!=1) {
                    cout <<"Malicious security for shuffle proof failed"<<endl;
                    exit(1);
                }


                //Receiver receives X,Y
                receivePoint(io, &(rs->X0), rs->group, rs->ctx);
                receivePoint(io, &(rs->X1), rs->group, rs->ctx);
                receivePoint(io, &(rs->Y0), rs->group, rs->ctx);
                receivePoint(io, &(rs->Y1), rs->group, rs->ctx);

                if (verifyReX(io, rs, com_alpha_beta[y], com_alpha_beta[y+ell])!=1) {
                    cout <<"Verification of PRF failed"<<endl;
                    exit(1);
                }


                /*                //Verify multiplication proof
                        if (verifyMul(io, rs->T0, rs->T1, rs->X0, rs->X1, com_alpha_beta[y], rs->g1, rs->g2, rs->group, rs->ctx)!=1) {
                            cout <<"Verification of multiplication (1) failed"<<endl;
                            exit(1);
                        }

                        if (verifyMul(io, rs->U0, rs->U1, rs->Y0, rs->Y1, com_alpha_beta[ell+y], rs->g1, rs->g2, rs->group, rs->ctx)!=1) {
                            cout <<"Verification of multiplication (2) failed"<<endl;
                            exit(1);
                        }*/

                //Shuffle back
                receiverStep3(x[y], rs);

                //Send P, P', Q, Q'
                sendPoint(io, rs->P0, rs->group, rs->ctx);
                sendPoint(io, rs->P1, rs->group, rs->ctx);
                sendPoint(io, rs->Pp0, rs->group, rs->ctx);
                sendPoint(io, rs->Pp1, rs->group, rs->ctx);
                sendPoint(io, rs->Q0, rs->group, rs->ctx);
                sendPoint(io, rs->Q1, rs->group, rs->ctx);
                sendPoint(io, rs->Qp0, rs->group, rs->ctx);
                sendPoint(io, rs->Qp1, rs->group, rs->ctx);


                if (proveShuffle(io, rs->pk, bX, bOMX, r_com_x_i, r_com_one_minus_x_i, rs->randomize_back_r, rs->X0, rs->X1, rs->Y0, rs->Y1, rs->g1, rs->g2, rs->group, rs->ctx)!=1) {
                    cout <<"Malicious security for shuffle back proof failed"<<endl;
                    exit(1);
                }


                unsigned char *recprf = receiverPRF(rs);
                free(recprf);

                //Done, clean up memory
                BN_free(bX);
                BN_free(bOMX);
                BN_free(r_com_x_i);
                EC_POINT_free(com_x_i);
                BN_free(r_com_one_minus_x_i);
                EC_POINT_free(com_one_minus_x_i);
                EC_POINT_free(com_sum);

                total_time += time_from(start);
		cpu_total_time += cpu_time_from(cpu_start);
            }
            free(x);
            free(one_minus_x);

            for (int i = 0; i<2*ell; i++) {
                EC_POINT_free(com_alpha_beta[i]);
            }
            free(com_alpha_beta);

        } else { //SENDER
            ss = initializeSender(group, g1, g2, ell, 128);
            auto start = clock_start(); //Wall time
	    std::clock_t cpu_start = std::clock(); //CPU time
 
            //Verify that V and D are encryptions of 1 and 0
            //receive V_0, D_0
            EC_POINT *receiver_pk;
            receivePoint(io, &receiver_pk, group, ctx);
            receivePoint(io, &(ss->V0), group, ctx);
            receivePoint(io, &(ss->V1), group, ctx);
            receivePoint(io, &(ss->D0), group, ctx);
            receivePoint(io, &(ss->D1), group, ctx);

            BIGNUM *zero = BN_new();
            BN_zero(zero);
            BIGNUM *one = BN_new();
            BN_one(one);

            if (verifyEnc(io, receiver_pk, ss->V0, ss->V1, one, ss->group, ss->g1, ss->g2, ss->ctx)!=1) {
                cout <<"Cannot verify V"<<endl;
                exit(1);
            }
            if (verifyEnc(io, receiver_pk, ss->D0, ss->D1, zero, ss->group, ss->g1, ss->g2, ss->ctx)!=1) {
                cout <<"Cannot verify D"<<endl;
                exit(1);
            }

            //Prove knowledge of alphas, betas within commitments
            BIGNUM ** com_r_alpha_beta = (BIGNUM **) malloc(2*ell*sizeof(BIGNUM*));
            for (int i = 0; i<ell; i++) {
                com_r_alpha_beta[i] = BN_new();
                com_r_alpha_beta[i+ell] = BN_new();
            }

            if (proveCommitments(io, ss, ell, com_r_alpha_beta)!=1) {
                cout <<"Malicious security for commitments failed"<<endl;
                exit(1);
            }
            total_time +=time_from(start);
            cpu_total_time += cpu_time_from(cpu_start);

	    
            for( int y = 0; y < ell; y++) {

                start = clock_start();
		cpu_start = std::clock();
		
                //Verify that x_i and 1-x_i are bits
                EC_POINT *com_x_i;
                if (verifyBit(io, &com_x_i, group, g1, g2, ctx)!=1) {
                    cout <<"bit verification of x_i failed"<<endl;
                }

                EC_POINT *com_one_minus_x_i;
                if (verifyBit(io, &com_one_minus_x_i, group, g1, g2, ctx)!=1) {
                    cout <<"bit verification of 1-x_i failed"<<endl;
                }

                //Verify that (x_i + 1-x_i) is a bit
                EC_POINT *sum;
                if (verifyBit(io, &sum, ss->group, ss->g1, ss->g2, ss->ctx)!=1) {
                    cout <<"bit verification of sum failed in part 1"<<endl;
                }
                EC_POINT *tmp = EC_POINT_new(ss->group);
                EC_POINT_add(ss->group, tmp, com_x_i, com_one_minus_x_i, ss->ctx);
                if(EC_POINT_cmp(ss->group, sum, tmp, ss->ctx)!=0) {
                    cout <<"bit verification of sum failed in part 2"<<endl;
                }
                EC_POINT_free(tmp);

                //Sender receives c,c',d,d'
                EC_POINT *c0, *c1, *cp0, *cp1, *d0, *d1, *dp0, *dp1;

                receivePoint(io, &c0, ss->group, ss->ctx);
                receivePoint(io, &c1, ss->group, ss->ctx);
                receivePoint(io, &cp0, ss->group, ss->ctx);
                receivePoint(io, &cp1, ss->group, ss->ctx);
                receivePoint(io, &d0, ss->group, ss->ctx);
                receivePoint(io, &d1, ss->group, ss->ctx);
                receivePoint(io, &dp0, ss->group, ss->ctx);
                receivePoint(io, &dp1, ss->group, ss->ctx);

                //Verify shuffle
                if (verifyShuffle(io, receiver_pk, ss->V0, ss->V1, ss->D0, ss->D1, c0, c1, cp0, cp1, d0, d1, dp0, dp1, com_x_i, com_one_minus_x_i, ss->g1, ss->g2, ss->group, ss->ctx)!=1) {
                    cout <<"Verify shuffle proof failed"<<endl;
                    exit(1);
                }

                //Sender computes T, U
                senderStep1c(ss, c0, c1, cp0, cp1, d0, d1, dp0, dp1);

                BIGNUM *r_renc_X = BN_new();
                BIGNUM *r_renc_Y = BN_new();

                senderStep2(ss, y, r_renc_X, r_renc_Y, receiver_pk);

                //Send X,Y to receiver
                sendPoint(io, ss->X0, ss->group, ss->ctx);
                sendPoint(io, ss->X1, ss->group, ss->ctx);
                sendPoint(io, ss->Y0, ss->group, ss->ctx);
                sendPoint(io, ss->Y1, ss->group, ss->ctx);

                if (proveReX(io, ss, receiver_pk, ss->a[y], com_r_alpha_beta[y], r_renc_X, ss->b[y], com_r_alpha_beta[y+ell], r_renc_Y)!=1) {
                    cout <<"Malicious security for ReX failed"<<endl;
                    exit(1);
                }

                BN_free(r_renc_X);
                BN_free(r_renc_Y);

                /*
                        //Prove correct multiplication
                        if (proveMul(io, ss->T0, ss->T1, ss->a[y], com_r_alpha_beta[y], ss->g1, ss->g2, ss->group, ss->ctx)!=1) {
                            cout <<"Malicious security for multiplication proof (1) failed"<<endl;
                            exit(1);
                        }
                        if (proveMul(io, ss->U0, ss->U1, ss->b[y], com_r_alpha_beta[ell+y], ss->g1, ss->g2, ss->group, ss->ctx)!=1) {
                            cout <<"Malicious security for multiplication proof (2) failed"<<endl;
                            exit(1);
                        }
                */


                //Receive P, P', Q, Q'
                EC_POINT *p0, *p1, *pp0, *pp1, *q0, *q1, *qp0, *qp1;
                receivePoint(io, &p0, ss->group, ss->ctx);
                receivePoint(io, &p1, ss->group, ss->ctx);
                receivePoint(io, &pp0, ss->group, ss->ctx);
                receivePoint(io, &pp1, ss->group, ss->ctx);
                receivePoint(io, &q0, ss->group, ss->ctx);
                receivePoint(io, &q1, ss->group, ss->ctx);
                receivePoint(io, &qp0, ss->group, ss->ctx);
                receivePoint(io, &qp1, ss->group, ss->ctx);

                //Verify shuffle
                if (verifyShuffle(io, receiver_pk, ss->X0, ss->X1, ss->Y0, ss->Y1, p0, p1, pp0, pp1, q0, q1, qp0, qp1, com_x_i, com_one_minus_x_i, ss->g1, ss->g2, ss->group, ss->ctx)!=1) {
                    cout <<"Verify shuffle back proof failed"<<endl;
                    exit(1);
                }



                //Update internal state V_i, D_i!
                EC_POINT_add(group, ss->V0, p0, qp0, ctx);
                EC_POINT_add(group, ss->V1, p1, qp1, ctx);
                EC_POINT_add(group, ss->D0, pp0, q0, ctx);
                EC_POINT_add(group, ss->D1, pp1, q1, ctx);

                //Done, clean up memory
                EC_POINT_free(p0);
                EC_POINT_free(p1);
                EC_POINT_free(pp0);
                EC_POINT_free(pp1);
                EC_POINT_free(q0);
                EC_POINT_free(q1);
                EC_POINT_free(qp0);
                EC_POINT_free(qp1);
                EC_POINT_free(sum);
                EC_POINT_free(com_x_i);
                EC_POINT_free(com_one_minus_x_i);

                total_time += time_from(start);
		cpu_total_time += cpu_time_from(cpu_start);
            }
            for (int i = 0; i<ell; i++) {
                BN_free(com_r_alpha_beta[i]);
                BN_free(com_r_alpha_beta[i+ell]);
            }
            free(com_r_alpha_beta);

            EC_POINT_free(ss->D0);
            EC_POINT_free(ss->D1);
            EC_POINT_free(ss->V0);
            EC_POINT_free(ss->V1);
            EC_POINT_free(receiver_pk);
            BN_free(one);
            BN_free(zero);
        }

    }
    string pname = (party == SENDER) ? "SENDER" : "RECEIVER";
    printf("Party %s, total CPU time: %.2f ms (%.2f ms per IOPRF, %.2f ms per IOPRF round), total wall time: %.2f ms (%.2f ms per IOPRF), IOPRF length: %d, total data sent: %.2f kB (%.2f kB per IOPRF)\n",&(pname[0]), cpu_total_time,cpu_total_time/runs,cpu_total_time/(runs*ell),total_time/1000,total_time/(runs*1000), ell,((double)io->counter)/((double)(1024)),((double)io->counter)/((double)(1024*runs)));


    EC_POINT_free(g1);
    EC_POINT_free(g2);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}

int main(int argc, char ** argv) {
    if (argc!=1) {
        if (strcmp(argv[1],"gen")==0) {
            createParameterFile();
            cout <<"Parameters created."<<endl;
            exit(1);
        }
    }


    if (argc!=5) {
        cout <<"You have to specify which party (1=Alice=sender or 2=Bob=receiver) and which port (e.g., 12345) you are, the string (e.g., 101101), and the number of runs."<<endl;
        return -1;
    }

    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party == SENDER ? nullptr:"127.0.0.1", port);

    int runs = atoi(argv[4]);

    if (party == RECEIVER) {
        return ioprf(argv[3], strlen(argv[3]), io, party, runs);
    } else {//SENDER
        return ioprf(NULL, strlen(argv[3]), io, party, runs);
    }



}
