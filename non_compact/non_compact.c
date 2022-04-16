#include "non_compact.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../mceliece348864/nist/rng.h"
#include "../mceliece348864/crypto_kem.h"

void otp(unsigned char *out, unsigned long long length, const unsigned char *in1, const unsigned char *in2){

	unsigned long long i;

	for(i = 0; i < length; i++){
		out[i] = in1[i] ^ in2[i];
	}
}


//Init
Ciphertext init(){
	Ciphertext c;

	//Allocate memory for message part of ciphertext
	c.c_m = calloc(crypto_kem_BYTES, 1);	
	
	//Allocate memory for symmetric key part of ciphertext
	for(int i = 0; i < 50; i++)
		c.c_k[i] = malloc(crypto_kem_CIPHERTEXTBYTES);

	//Number of operations is 0, there are 0 symmetric keys
	c.num_ops = 0;

	return c;
}


//Clean up
void cleanup(Ciphertext *c){
	free(c->c_m);

	for(int i = 0; i < 50; i++){
		free(c->c_k[i]);
	}
}

//Encrypt
void non_compact_encrypt(const unsigned char *pk, const unsigned char *m, Ciphertext *c){
	unsigned char *k = malloc(crypto_kem_BYTES);

	//Kem to get symmetric keys
	crypto_kem_enc(c->c_k[0], k, pk);

	//Encrypt message with otp
	otp(c->c_m, crypto_kem_BYTES, m, k);

	c->num_ops = 1;

	free(k);
}

//Computation
void compute(const Ciphertext *c1, const Ciphertext *c2, Ciphertext *c){
	if(c1->num_ops + c2->num_ops > 50){
		printf("Error in compute. Number of operations exceeds space.\n");
		exit(1);
	}

	unsigned char* copies[50];
	for(int i = 0; i < 50; i++)
		copies[i] = malloc(crypto_kem_CIPHERTEXTBYTES);

	int count = 0;

	//Compute one time pad on cipher text
	otp(c->c_m, crypto_kem_BYTES, c1->c_m, c2->c_m);

	int c1_ops = c1->num_ops;
	int c2_ops = c2->num_ops;
	
	//Append symmetric keys to c
	for(int i = 0; i < c1_ops; i++){
		memmove(copies[count++], c1->c_k[i], crypto_kem_CIPHERTEXTBYTES);
	}

	for(int i = 0; i < c2_ops; i++){
		memmove(copies[count++], c2->c_k[i], crypto_kem_CIPHERTEXTBYTES);	
	}

	c->num_ops = c1->num_ops + c2->num_ops;
	for(int i = 0; i < count; i++){
		memmove(c->c_k[i], copies[i], crypto_kem_CIPHERTEXTBYTES);
		free(copies[i]);
	}
}


//Decrypt
void non_compact_decrypt(const unsigned char *sk, const Ciphertext* c, unsigned char *m){
	unsigned char *k = malloc(crypto_kem_BYTES);
	
	//Copy c_m into m to start with
	memcpy(m, c->c_m, crypto_kem_BYTES);

	for(int i = 0; i < c->num_ops; i++){
		//Get symmetric key
		crypto_kem_dec(k, c->c_k[i], sk);
		
		//Decrypt with otp
		otp(m, crypto_kem_BYTES, m, k); 
	}


	free(k);
}
