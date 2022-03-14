#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../mceliece348864/nist/rng.h"
#include "../mceliece348864/crypto_kem.h"
#include "../mceliece348864/params.h"
#include "compact_enc.h"
#include "../mceliece348864/decrypt.h"
#include "../mceliece348864/encrypt.h"
#include "../mceliece348864/api.h"

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
	
	//Output key pair to files
	FILE *pk_file = fopen("public_key.txt", "w");
	FILE *sk_file = fopen("secret_key.txt", "w");

	fprintBstr(pk_file, "", pk, crypto_kem_PUBLICKEYBYTES);
	fprintBstr(sk_file, "", sk, crypto_kem_SECRETKEYBYTES);

	fclose(pk_file);
	fclose(sk_file);

	fprintf(stdout, "Public key outputed to \"public_key.txt\"\n");
	fprintf(stdout, "Secret key outputed to \"secret_key.txt\"\n\n");

	

	


	//Generate error vectors e1 and e2 for m1 and m2
	unsigned char e1_add[SYS_N/8] = {0};
    unsigned char *e1 = e1_add;

	unsigned char e2_add[SYS_N/8] = {0};
    unsigned char *e2 = e2_add;
	

	//Allocate memory for c1 and c2
	unsigned char *c1  = malloc(SYND_BYTES);
	unsigned char *c2  = malloc(SYND_BYTES);



    //Generate error vector of length N-2 with t/2-2 errors
	gen_e(e1);
	gen_e(e2);
	
    //Append messages, (101) and (110)
	e1[SYS_N/8-1] |= 0x06;
	e2[SYS_N/8-1] |= 0x05;

    fprintf(stdout, "m1: %02X\n", e1[SYS_N/8-1]);
    fprintf(stdout, "m2: %02X\n", e2[SYS_N/8-1]);

    fprintBstr(stdout, "e1: ", e1, SYS_N/8);
    fprintBstr(stdout, "e2: ", e2, SYS_N/8);

    //Compute sydrome for message of length N
	syndrome(c1, pk, e1);
	syndrome(c2, pk, e2);



    //Perform bitwise xor on ciphertexts
    unsigned char *c  = malloc(SYND_BYTES);
    otp(c, SYND_BYTES, c1, c2); 
	



    //Make room for error vector for result
    unsigned char t1_add[SYS_N/8] = {1};
    unsigned char *t1 = t1_add;

    //Decrypt error vector with t errors
    decrypt(t1, sk+40, c);

    fprintBstr(stdout, "\nc1 + c2 error vector: ", t1, SYS_N/8);
    fprintf(stdout, "c1 + c2: %02X\n", t1[SYS_N/8-1]);

	free(c1);
	free(c2);
    free(c);

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
