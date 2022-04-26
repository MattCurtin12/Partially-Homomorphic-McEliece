/* Description:
 * 	Generic homomorphic encryption over a size N group of integers.
 *	
 * Components:
 * 	- A symmetric key generator
 *	- A key encapsulation mechanism using one time pad
 *	- A key decapsulation mechanism using one time pad
 *	- An encryption scheme using the KEM
 *	- A decyrption scheme using the DEM
 *	- A homomorphic adding funciton over N
 *
 * Idea:
 * 	1. Let: m1, m2 be from group of size N 
 * 	2. Generate a key k from random
 * 	3. Encapsulate Random keys
 * 		a. m_k1, m_k2 from random. 
 * 		b. c_k1 = m_k1 ^ k 	
 * 		   c_k2 = m_k2 ^ k 
 * 	4. Encrypt m1, m2 to get c1, c2
 * 		c1 = <c_k1, s1 = (m1 + m_k1) % N>
 * 		c2 = <c_k2, s2 = (m2 + m_k2) % N>
 * 	5. Add ciphertexts together c = c1+c2 
 *		c = < c_k1, c_k2, s = (s1 + s2) % N> 
 *	6. Decrypt c to get m
 *		m_k1 = c_k1 ^ k 
 *		m_k2 = c_k2 ^ k 
 *		
 *		m = (S - m_k1 - m_k2) % N 
 */

#include <stdio.h>
#include <stdlib.h>

// Length of the group. 2^32 or max value of unsigned long int + 1
#define N 4294967296

// Size of ciphertexts, messages, keys in bytes
#define SIZE 4

// Open /dev/urandom to this location
FILE* RNG;

// Ciphertext
// Contains a sum component and a list of KEM
typedef struct{
	unsigned long int sum;
	unsigned long int c_k[50];
	unsigned int count;
} Ciphertext;


// Generate symmetric key
// K : User key
void gen_key(unsigned long int* k){
	fread(k, SIZE, 1, RNG);
}

// Encapsulate
// m_k	: plaintext key
// c_k	: encapsulated key
// K   	: User key 
void encaps(unsigned long int* m_k, unsigned long int* c_k, unsigned long int k){
	fread(m_k, SIZE, 1, RNG);
       	*c_k = *m_k ^ k;
}

// Decapsulate
// m_k  : plaintext key
// c_k  : encapsulated key
// K    : User key
void decaps(unsigned long int* m_k, unsigned long int* c_k, unsigned long int k){
	*m_k = *c_k ^ k;
}


// Encrypt a message
// m	: plaintext message
// c	: outputed ciphertext
// k	: user key
void encrypt(unsigned int m, Ciphertext* c, unsigned long int k){
	
	c->sum = 0;
	c-> count = 0;

	unsigned long int m_k, c_k;
	encaps(&m_k, &c_k, k);

	c->sum =(m + m_k) % N;
	c->c_k[c->count] = c_k;
	c->count++;
}

// Decrypt a message
// m     : plaintext message
// c     : outputed ciphertext
// k     : user key
void decrypt(unsigned long int* m,  Ciphertext* c, unsigned long int k){
	
	*m = c->sum;
	unsigned long int m_k;

	for(int i = 0; i < c->count; i++){
		decaps(&m_k,&(c->c_k[i]), k);
		*m = (*m - m_k) % N;
	}
}

// Add ciphertext 2 to ciphertext 1
void add(Ciphertext* c1, Ciphertext* c2){
	if(c1->count + c2->count >= 50){
		printf("Ciphertext size exceeded\n");
		return;
	}

	//Add sums
	c1->sum = (c1->sum + c2->sum) % N;

	//Keep encapsulated keys
	for(int i = 0; i < c2->count; i++){
		c1->c_k[c1->count] = c2->c_k[i];
		c1->count+=1;	
	}
}

// Print information about ciphertexts
void print_c( Ciphertext* c){
	printf("Sum: %lu\tCount: %u\n", c->sum, c->count);
	printf("Keys: ");
	for(int i = 0; i < c->count; i++){
		printf("%lu ", c->c_k[i]);
	}	
	printf("\n");
}

int main(){

	//Initialize random number generation
        RNG = fopen("/dev/urandom", "r");

        if(!RNG){
                printf("Problem opening /dev/urandom \n");
                return 1;
        }


	unsigned long int k;
	gen_key(&k);

	//40 trials with increasing ciphertexts operations
	for(int i = 0; i < 40; i++){
		
		printf("*******\tTrial %d ********\n\n", i);

		//Set sum equal to 0 initially
		Ciphertext summation;
		summation.count = 0;
		summation.sum = 0;

		//Keep track of truth
		unsigned long int actual_sum = 0;

		printf("Terms:\n");
		for(int j = 0; j < i; j++){
			//Random Number:
			unsigned long int message;
			fread(&message, SIZE, 1, RNG);
			
			printf("%12lu\n", message);


			Ciphertext term;
			encrypt(message, &term, k);

			add(&summation, &term);

			actual_sum = (actual_sum + message) % N;
		}

		printf("\n\nFinal Ciphertext:\n");
		print_c(&summation);
		unsigned long int computed_sum;
		decrypt(&computed_sum, &summation, k);
		printf("\nActual Sum: %lu\tComputed Sum: %lu\tSuccess: %d\n\n\n\n", actual_sum, computed_sum, actual_sum == computed_sum);

	}

	//Cleanup
	fclose(RNG);
        return 0;

}

