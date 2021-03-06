#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../mceliece348864/nist/rng.h"
#include "../mceliece348864/crypto_kem.h"
#include "non_compact.h"

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

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





	//Init plaintexts
	unsigned char *m1, *m2;
	m1 = malloc(crypto_kem_BYTES);
	m2 = malloc(crypto_kem_BYTES);

	for(int i = 0; i < crypto_kem_BYTES; i++){
		m1[i] = 0;
		m2[i] = 0;
	}

	//Set m1 = 110, m2 = 101
	m1[crypto_kem_BYTES - 1] = 0x06;
	m2[crypto_kem_BYTES - 1] = 0X05; 

	fprintBstr(stdout, "Original m1: ", m1, crypto_kem_BYTES);
	fprintBstr(stdout, "Original m2: ", m2, crypto_kem_BYTES);
	fprintf(stdout, "\n");





	//Encrypt plaintexts
	unsigned char *c1, *ss1, *k1;	//ciphertext, plain shared secret key, encrypted key
	unsigned char *c2, *ss2, *k2;

	c1  = malloc(crypto_kem_BYTES);
	ss1 = malloc(crypto_kem_BYTES);
	k1  = malloc(crypto_kem_CIPHERTEXTBYTES);	//The encrypted key is the ciphertext in the kem

	c2  = malloc(crypto_kem_BYTES);
	ss2 = malloc(crypto_kem_BYTES);
	k2  = malloc(crypto_kem_CIPHERTEXTBYTES);


	//Generate first secret key
	if( crypto_kem_enc(k1, ss1, pk) != 0){
		fprintf(stderr, "crytpo_kem_enc\n");
		return 2;
	}

	//Generate second secret key
	if( crypto_kem_enc(k2, ss2, pk) != 0){
		fprintf(stderr, "crytpo_kem_enc\n");
		return 2;
	}


	//Encrypt first message with shared secret key using one time pad
	otp(c1, crypto_kem_BYTES, m1, ss1);

	//Encrypt second message with shared secret key using one time pad
	otp(c2, crypto_kem_BYTES, m2, ss2);


	fprintBstr(stdout, "c1: ", c1, crypto_kem_BYTES);
	fprintBstr(stdout, "c2: ", c2, crypto_kem_BYTES);
	fprintf(stdout, "\n");




	//Decrypt c1 and c2 to show encryption worked
	unsigned char *n1, *n2;
	n1 = malloc(crypto_kem_BYTES);
	n2 = malloc(crypto_kem_BYTES);

	otp(n1, crypto_kem_BYTES, c1, ss1);
	otp(n2, crypto_kem_BYTES, c2, ss2);

	fprintBstr(stdout, "Decrypted m1: ", n1, crypto_kem_BYTES);
	fprintBstr(stdout, "Decrypted m2: ", n2, crypto_kem_BYTES);
	fprintf(stdout, "\n");





	//Perform homomorphic operation on c1 and c2 (OTP) c' = c1 + c2
	unsigned char* c = malloc(crypto_kem_BYTES);
	otp(c, crypto_kem_BYTES, c1, c2);

	fprintBstr(stdout, "c\' = c1 + c2: ", c, crypto_kem_BYTES);
	fprintf(stdout, "\n");






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

	fprintBstr(stdout, "Decrypted c':", m, crypto_kem_BYTES);
	fprintf(stdout, "\n");


	#define TIMING
	#ifdef TIMING

	#include <time.h>
	//Initialize messages
	fprintf(stdout, "Messages:\n");
	unsigned char* messages[50];
	for(int i = 0; i < 50; i++){
		messages[i] = calloc(crypto_kem_BYTES, 1);
		randombytes(messages[i], crypto_kem_BYTES);
		fprintBstr(stdout, "", messages[i], crypto_kem_BYTES);
	}

	//Times
	clock_t start, end, enc_average = 0;

	fprintf(stdout, "\n*Encryption*\n");
	//Encrypt all messages
	Ciphertext ciphertexts[50];
	for(int i = 0; i < 50; i++){
		ciphertexts[i] = init();	
		
		start = clock();	
		non_compact_encrypt(pk, messages[i], &ciphertexts[i]);
		end = clock();

		enc_average += end - start;
		
		fprintf(stdout, "Clock cycles for encryption %d: %ld\n", i+1, end-start);	
	}

	enc_average /= 50.0f;
	
	fprintf(stdout, "Average number of clock cycles per encryption: %ld\n", enc_average);
	fprintf(stdout, "Average time per encryption: %f seconds\n", (double)enc_average / CLOCKS_PER_SEC);

	
	

	//Computation
	Ciphertext total = init();
	
	unsigned char* message = malloc(crypto_kem_BYTES);
	clock_t comp_average = 0, dec_average = 0;

	fprintf(stdout, "\n*Computation*\n");	
	
	for(int i = 0; i < 50; i++){
		start = clock();
		compute(&ciphertexts[i], &total, &total);
		end = clock();

		comp_average += end - start;

		fprintf(stdout, "Computation %d\t|\tCycles: %ld\tSeconds:%f\n", i+1, end-start, (double)(end-start)/CLOCKS_PER_SEC);
		
		
		start = clock();
		non_compact_decrypt(sk, &total, message);
		end = clock();

		dec_average += end - start;
		fprintf(stdout, "Decryption %d\t|\tCycles: %ld\tSeconds:%f\n", i+1, end-start, (double)(end-start)/CLOCKS_PER_SEC);

	}
	comp_average /= 50.0f;

        fprintf(stdout, "Average number of clock cycles per computation: %ld\n", comp_average);
        fprintf(stdout, "Average time per computation: %f seconds\n", (double)comp_average / CLOCKS_PER_SEC);
	
	dec_average /= 50.0f;

	fprintf(stdout, "Average number of clock cycles per decryption: %ld\n", dec_average);
        fprintf(stdout, "Average time per decryption: %f seconds\n", (double)dec_average / CLOCKS_PER_SEC);

	non_compact_decrypt(sk, &total, message);
	fprintf(stdout, "\n*Final*\n");
	fprintBstr(stdout, "", message, crypto_kem_BYTES);
	
	for(int i = 0; i < 50; i++){
		start = clock();
		non_compact_decrypt(sk, &ciphertexts[i], message); 
		end = clock();

		dec_average += end - start;
		fprintf(stdout, "Decryption %d\t|\tCycles: %ld\tSeconds:%f\n", i+1, end-start, (double)(end-start)/CLOCKS_PER_SEC);

	}

	dec_average /= 50.0f;

        fprintf(stdout, "Average number of clock cycles per decryption: %ld\n", dec_average);
        fprintf(stdout, "Average time per decryption: %f seconds\n", (double)dec_average / CLOCKS_PER_SEC);

	cleanup(&total);
	free(message);
	for(int i = 0; i < 50; i++){
        	free(messages[i]);
		cleanup(&ciphertexts[i]);
	}

	#endif



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

