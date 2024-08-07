/*
   PQCgenKAT_kem.c
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
   + mods from djb: see KATNOTES
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rng.h"
#include "crypto_kem.h"
#include "pk_gen.h"
#include "root.h"
#include "encrypt.h"
#include "decrypt.h"
#include "operations.h"
#include "custom_util.h"

#include <sys/time.h>
//#include <valgrind/callgrind.h>

#ifndef KATNUM
#define KATNUM 100  // or whatever number you want to use
#endif

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_CRYPTO_FAILURE  -4

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

unsigned char entropy_input[48];
unsigned char (*seed)[48];

double sum_keygen, sum_enc, sum_dec;
int times_keygen, times_enc, times_dec;

double sum_total;
int times_total;

// Declare these variables if they're used in the timing results
double sum_elim, sum_synd, sum_syndrome, sum_keyop, sum_encrypt, sum_decrypt;
int times_elim, times_synd, times_syndrome, times_keyop, times_encrypt, times_decrypt;

int main()
{
    FILE                *fp_req, *fp_rsp;
    int                 ret_val;
    int i;
    unsigned char *ct = 0;
    unsigned char *ss = 0;
    unsigned char *ss1 = 0;
    unsigned char *pk = 0;
    unsigned char *sk = 0;

    struct timeval start_keygen, end_keygen, start_enc, end_enc, start_dec, end_dec;

    // Allocate memory for seed
    seed = malloc(KATNUM * sizeof(*seed));
    if (!seed) {
        fprintf(stderr, "Memory allocation failed for seed\n");
        return KAT_CRYPTO_FAILURE;
    }

    for (i=0; i<48; i++)
        entropy_input[i] = i;
    randombytes_init(entropy_input, NULL, 256);

    for (i=0; i<KATNUM; i++)
        randombytes(seed[i], 48);

    fp_req = fopen("kat_kem.req", "w");
    if (!fp_req) {
        free(seed);
        return KAT_FILE_OPEN_ERROR;
    }

    for (i=0; i<KATNUM; i++) {
        fprintf(fp_req, "count = %d\n", i);
        fprintBstr(fp_req, "seed = ", seed[i], 48);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "ct =\n");
        fprintf(fp_req, "ss =\n\n");
    }

    fclose(fp_req);

    fp_rsp = fopen("kat_kem.rsp", "w");
    if (!fp_rsp) {
        free(seed);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# kem/%s\n\n", crypto_kem_PRIMITIVE);

    for (i=0; i<KATNUM; i++) {
        if (!ct) ct = malloc(crypto_kem_CIPHERTEXTBYTES);
        if (!ct) abort();
        if (!ss) ss = malloc(crypto_kem_BYTES);
        if (!ss) abort();
        if (!ss1) ss1 = malloc(crypto_kem_BYTES);
        if (!ss1) abort();
        if (!pk) pk = malloc(crypto_kem_PUBLICKEYBYTES);
        if (!pk) abort();
        if (!sk) sk = malloc(crypto_kem_SECRETKEYBYTES);
        if (!sk) abort();

        randombytes_init(seed[i], NULL, 256);

        fprintf(fp_rsp, "count = %d\n", i);
        fprintBstr(fp_rsp, "seed = ", seed[i], 48);
       
        gettimeofday(&start_keygen, NULL);
        ret_val = crypto_kem_keypair(pk, sk);
        gettimeofday(&end_keygen, NULL);
        get_event_time(&start_keygen, &end_keygen, &sum_keygen, &times_keygen);
        get_event_time(&start_keygen, &end_keygen, &sum_total, &times_total);
        times_total = times_total - 1;

        if (ret_val != 0) {
            fprintf(stderr, "crypto_kem_keypair returned <%d>\n", ret_val);
            free(seed);
            free(ct);
            free(ss);
            free(ss1);
            free(pk);
            free(sk);
            fclose(fp_rsp);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, crypto_kem_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, crypto_kem_SECRETKEYBYTES);

        gettimeofday(&start_enc, NULL);
        ret_val = crypto_kem_enc(ct, ss, pk);
        gettimeofday(&end_enc, NULL);
        get_event_time(&start_enc, &end_enc, &sum_enc, &times_enc);
        get_event_time(&start_enc, &end_enc, &sum_total, &times_total);
        times_total = times_total - 1;

        if (ret_val != 0) {
            fprintf(stderr, "crypto_kem_enc returned <%d>\n", ret_val);
            free(seed);
            free(ct);
            free(ss);
            free(ss1);
            free(pk);
            free(sk);
            fclose(fp_rsp);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "ct = ", ct, crypto_kem_CIPHERTEXTBYTES);
        fprintBstr(fp_rsp, "ss = ", ss, crypto_kem_BYTES);
        
        fprintf(fp_rsp, "\n");

        gettimeofday(&start_dec, NULL);
        ret_val =  crypto_kem_dec(ss1, ct, sk);
        gettimeofday(&end_dec, NULL);
        get_event_time(&start_dec, &end_dec, &sum_dec, &times_dec);
        get_event_time(&start_dec, &end_dec, &sum_total, &times_total);

        if (ret_val != 0) {
            fprintf(stderr, "crypto_kem_dec returned <%d>\n", ret_val);
            free(seed);
            free(ct);
            free(ss);
            free(ss1);
            free(pk);
            free(sk);
            fclose(fp_rsp);
            return KAT_CRYPTO_FAILURE;
        }
        
        if (memcmp(ss, ss1, crypto_kem_BYTES)) {
            fprintf(stderr, "crypto_kem_dec returned bad 'ss' value\n");
            free(seed);
            free(ct);
            free(ss);
            free(ss1);
            free(pk);
            free(sk);
            fclose(fp_rsp);
            return KAT_CRYPTO_FAILURE;
        }
    }
    
    fclose(fp_rsp);

    printf("\n\t**********TIMING RESULTS**********\t\n");    
    printf("Elim kernel Part ");
    print_event_execution_time(&sum_elim, &times_elim);
    printf("Synd kernel Part ");
    print_event_execution_time(&sum_synd, &times_synd);
    printf("Syndrome kernel Part ");
    print_event_execution_time(&sum_syndrome, &times_syndrome);
    
    printf("Key Generation Part ");
    print_event_execution_time(&sum_keygen, &times_keygen);
    printf("Encapsulate Part ");
    print_event_execution_time(&sum_enc, &times_enc);
    printf("Decapsulate Part ");
    print_event_execution_time(&sum_dec, &times_dec);
    printf("Pk generation Part ");
    print_event_execution_time(&sum_keyop, &times_keyop);
    printf("Encryption Part ");
    print_event_execution_time(&sum_encrypt, &times_encrypt);
    printf("Decryption Part ");
    print_event_execution_time(&sum_decrypt, &times_decrypt);

    printf("Total Part ");
    print_event_execution_time(&sum_total, &times_decrypt);

    // Free allocated memory
    free(seed);
    free(ct);
    free(ss);
    free(ss1);
    free(pk);
    free(sk);

    return KAT_SUCCESS;
}

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long i;

    fprintf(fp, "%s", S);

    for (i=0; i<L; i++)
        fprintf(fp, "%02X", A[i]);

    if (L == 0)
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
