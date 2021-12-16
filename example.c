#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mceliece348864/nist/rng.h"
#include "mceliece348864/crypto_kem.h"


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
	
	
	//Public key, private key pair
	unsigned char *pk, *sk;
	pk = malloc(crypto_kem_PUBLICKEYBYTES);
    	sk = malloc(crypto_kem_SECRETKEYBYTES);
	
	//Generate key pair
	if( crypto_kem_keypair(pk, sk) != 0){
		fprintf(stderr, "crypto_kem_keypair\n");
		return 1;
	}

	//Message 1
	unsigned char *m1, *c1;		//Arbitrary message
	unsigned char *ss1, *k1;	//shared secret key: plain, encrypted
	m1  = malloc(crypto_kem_BYTES);
	c1  = malloc(crypto_kem_BYTES);
	ss1 = malloc(crypto_kem_BYTES);
	k1  = malloc(crypto_kem_CIPHERTEXTBYTES);

	//Generate random message 1
	randombytes(m1, crypto_kem_BYTES);
	randombytes_init(m1, NULL, 256);

	//Generate first secret key
	if( crypto_kem_enc(k1, ss1, pk) != 0){
		fprintf(stderr, "crytpo_kem_enc\n");
		return 2;
	}

	//Encrypt first message with shared secret key using one time pad
	otp(c1, crypto_kem_BYTES, m1, ss1);

	//Message 2
	unsigned char *m2, *c2;  	//Arbitrary message
        unsigned char *ss2, *k2; 	//shared secret key: plain, encrypted
        m2  = malloc(crypto_kem_BYTES);
        c2  = malloc(crypto_kem_BYTES);
        ss2 = malloc(crypto_kem_BYTES);
        k2  = malloc(crypto_kem_CIPHERTEXTBYTES);

        //Generate random message 1
        randombytes(m2, crypto_kem_BYTES);
        randombytes_init(m2, NULL, 256);

        //Generate second secret key
        if( crypto_kem_enc(k2, ss2, pk) != 0){
                fprintf(stderr, "crytpo_kem_enc\n");
                return 2;
        }

        //Encrypt second message with shared secret key using one time pad
        otp(c2, crypto_kem_BYTES, m2, ss2);


	//Perform homomorphic operation on c1 and c2 (OTP)
	unsigned char* c = malloc(crypto_kem_BYTES);
	otp(c, crypto_kem_BYTES, c1, c2);

	
	//Decode kems
	unsigned char *_ss1, *_ss2;
       	_ss1 = malloc(crypto_kem_BYTES);	//First shared secret key
	_ss2 = malloc(crypto_kem_BYTES);	//Second shred secret key
	
	if( crypto_kem_dec(_ss1, k1, sk) != 0 || crypto_kem_dec(_ss2, k2, sk) != 0){
		fprintf(stderr, "crytpo_kem_dec\n");
		return 3;
	}	


	//Decrypt message
	unsigned char *m = malloc(crypto_kem_BYTES);
	otp(m, crypto_kem_BYTES, c, _ss1);
	otp(m, crypto_kem_BYTES, m, ss2);
	
	
	//Show output
	fprintf(stdout, "\n[Messages]\n");
	fprintBstr(stdout, "Message 1:\t\t\t", m1, crypto_kem_BYTES);
	fprintBstr(stdout, "Message 2:\t\t\t", m2, crypto_kem_BYTES);
	fprintBstr(stdout, "Evaluated Message:\t\t", m, crypto_kem_BYTES);

	unsigned char *expected = malloc(crypto_kem_BYTES);
	otp(expected, crypto_kem_BYTES, m1, m2);
	fprintBstr(stdout, "Expected Message:\t\t", expected, crypto_kem_BYTES);
	
	fprintf(stdout, "\n[Shared Keys]\n");
	fprintBstr(stdout, "Shared Secret 1:\t\t", ss1, crypto_kem_BYTES);
	fprintBstr(stdout, "Shared Secret 2:\t\t", ss2, crypto_kem_BYTES);
	fprintBstr(stdout, "Evaluated Shared Secret 1:\t", _ss1, crypto_kem_BYTES);
	fprintBstr(stdout, "Evaluated Shared Secret 2:\t", _ss2, crypto_kem_BYTES);

	//Free memory
	free(pk);
	free(sk);

	free(m1);
	free(c1);
	free(ss1);
	free(k1);

	free(m2);
        free(c2);
        free(ss2);
        free(k2);	

	free(c);
	
	free(_ss1);
	free(_ss2);

	free(m);
	free(expected);
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
