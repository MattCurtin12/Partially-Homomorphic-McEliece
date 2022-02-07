#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../mceliece348864/nist/rng.h"
#include "../mceliece348864/crypto_kem.h"
#include "../mceliece348864/params.h"
#include "../mceliece348864/encrypt.h"
#include "../mceliece348864/decrypt.h"
#include "../mceliece348864/api.h"

#define WEIGHT_M 4				//the error correcting weight of messages
#define SYS_T_ORIG 64				//Weight of full message
#define SYS_T_ENC (SYS_T_ORIG - WEIGHT_M)/2	//Weight of e1 and e2

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

	

	

	//Initialize m1 and m2
	//Each message is 3 bits 
	unsigned char m1[SYS_N/8] = {0};
	unsigned char m2[SYS_N/8] = {0};
	
	m1[CRYPTO_BYTES - 1] = 0x05;
	m2[CRYPTO_BYTES - 1] = 0x06;
	
	fprintBstr(stdout, "m1: ", m1, CRYPTO_BYTES);
	fprintBstr(stdout, "m2: ", m2, CRYPTO_BYTES);


	//Encrypt c1 and c2 with new weight
	unsigned char *c1  = malloc(CRYPTO_CIPHERTEXTBYTES);
	unsigned char *c2  = malloc(CRYPTO_CIPHERTEXTBYTES);	

	//#undef SYS_T	
	//#define SYS_T SYS_T_ENC

	encrypt(c1, pk, m1);
	encrypt(c2, pk, m2);	

        //#undef SYS_T
        //#define SYS_T SYS_T_ORIG
	




	
	
	//Perform one time pad operation on ciphertexts
	unsigned char *c = malloc(crypto_kem_CIPHERTEXTBYTES);
	otp(c, crypto_kem_BYTES, c1, c2);
	
		


	//Decrypt c to find m
	unsigned char m[SYS_N/8] = {0};

	decrypt(m, sk, c1);
		

	fprintBstr(stdout, "M: ", m, CRYPTO_BYTES);
	


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
