#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../mceliece6688128/nist/rng.h"
#include "../mceliece6688128/crypto_kem.h"
#include "../mceliece6688128/params.h"
#include "compact_enc.h"
#include "../mceliece6688128/decrypt.h"
#include "../mceliece6688128/encrypt.h"
#include "../mceliece6688128/api.h"

#define CASES 100

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);
void otp(unsigned char *out, unsigned long long length, unsigned char *in1, unsigned char *in2);

unsigned char entropy_input[48];
unsigned char seed[48];

int main(){

	//Entropy and seed
	for (int i=0; i<48; i++)
		entropy_input[i] = i;

	randombytes_init(entropy_input, NULL, 256);

	randombytes(seed, 48);
	randombytes_init(seed, NULL, 256);





	//Public key, private key pair generation
	unsigned char *pk, *sk;
	pk = malloc(crypto_kem_PUBLICKEYBYTES);
	sk = malloc(crypto_kem_SECRETKEYBYTES);

	//Generate key pair
	if( crypto_kem_keypair(pk, sk) != 0){
		fprintf(stderr, "crypto_kem_keypair\n");
		return 1;
	}


	//Generate error vectors e1 and e2 for m1 and m2
	unsigned char e1_add[SYS_N/8] = {0};
	unsigned char *e1 = e1_add;

	unsigned char e2_add[SYS_N/8] = {0};
	unsigned char *e2 = e2_add;

	//Allocate memory for c1 and c2
	unsigned char *c1  = malloc(SYND_BYTES);
	unsigned char *c2  = malloc(SYND_BYTES);

    //Allocate memory for c
	unsigned char *c  = malloc(SYND_BYTES);

    //Allocate memory for decrypting single messages
    unsigned char *temp = malloc(SYS_N/8);
    unsigned char *temp2 = malloc(SYS_N/8);

    //Random messages
    unsigned char messages[CASES*2];
    randombytes(messages, CASES * 2);

    //Timing
    clock_t begin, end;
    clock_t encrypt_avg = 0, decrypt_single_avg = 0, decrypt_summed_avg = 0;

    fprintf(stdout,"Staring test cases\n");
    for(int i = 0; i < CASES; i++){
        printf("Test case: %d...\n", i);
        
        unsigned char m1, m2;
        m1 = messages[i] & 0x07;    //Get last three bits
        m2 = messages[i+1] & 0x07;
       
        printf("\tm1: %02X m2: %02X\n", m1, m2);
       

        //ENCRYPT
        begin = clock();
        
        //Generate error vector of length N-2 with t/2-2 errors
        gen_e(e1);
        gen_e(e2);
        
	    //Append messages, (101) and (110)
	    e1[SYS_N/8-1] |= m1;
	    e2[SYS_N/8-1] |= m2;

        //Compute sydrome for message of length N
        syndrome(c1, pk, e1);
        syndrome(c2, pk, e2);

        end = clock();
        encrypt_avg += end - begin;


        //DECRYPT SINGLE MESSAGES
        begin = clock();

        //decrypt
        decrypt(temp, sk+40, c1);
        decrypt(temp2, sk+40, c2);

        end = clock(); 
        decrypt_single_avg += end - begin;

        printf("\td1: %02X d2: %02X\n", temp[SYS_N/8-1] & 0x07, temp2[SYS_N/8-1] & 0x07); 
        memset(temp, 0, SYS_N/8);
        memset(temp2, 0, SYS_N/8);

        //Add messages
	    otp(c, SYND_BYTES, c1, c2); 

        //DECRYPT SUMMED MESSAGES
        begin = clock();

	    decrypt(temp, sk+40, c);

        end = clock();
        decrypt_summed_avg = end - begin;

        printf("\tExpected: %02X Result: %02X\n\n", m1 ^ m2, temp[SYS_N/8-1] & 0x07);
        memset(temp, 0, SYS_N/8);
        memset(c, 0, SYND_BYTES);
        memset(c1, 0, SYND_BYTES);
        memset(c2, 0, SYND_BYTES);
        memset(e1, 0, SYS_N/8);
        memset(e2, 0, SYS_N/8);

        fflush(stdout);
    }

    encrypt_avg /= CASES * 2;
    decrypt_single_avg /= CASES * 2;
    decrypt_summed_avg /= CASES;

    fprintf(stdout, "\n%20s | %15s | %15s\n", " ", "Clock Cycles", "Time (seconds)");
    fprintf(stdout, "%20s | %15ld | %15f\n", "Encryption Avg", encrypt_avg, (double)encrypt_avg / CLOCKS_PER_SEC);
    fprintf(stdout, "%20s | %15ld | %15f\n", "Single Decrypt Avg", decrypt_single_avg, (double)decrypt_single_avg / CLOCKS_PER_SEC);
    fprintf(stdout, "%20s | %15ld | %15f\n", "Summed Decrypt Avg", decrypt_summed_avg, (double)decrypt_summed_avg / CLOCKS_PER_SEC);



	free(c1);
	free(c2);
	free(c);
    free(temp);
    free(temp2);


	return 0;
}

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

void otp(unsigned char *out, unsigned long long length, unsigned char *in1, unsigned char *in2){

	unsigned long long i;

	for(i = 0; i < length; i++){
		out[i] = in1[i] ^ in2[i];
	}
}
