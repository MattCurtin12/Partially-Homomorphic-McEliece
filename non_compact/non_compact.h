

void otp(unsigned char *out, unsigned long long length, const unsigned char *in1, const unsigned char *in2);


//Ciphertext data type
typedef struct{
	unsigned char *c_m;	//Part of ciphertext containing message
	unsigned char *c_k[50];	//List of ciphertext containing symmetric keys
	unsigned int num_ops;	//Number of operations on ciphertext, aka number of symmetric keys

} Ciphertext;


//Init
Ciphertext init();

//Clean up
void cleanup(Ciphertext *c);

//Encrypt
void non_compact_encrypt(const unsigned char *pk, const unsigned char *m, Ciphertext *c); 

//Computation
void compute(const Ciphertext *c1, const Ciphertext *c2, Ciphertext *c);

//Decrypt
void non_compact_decrypt(const unsigned char *sk, const  Ciphertext *c, unsigned char *m);


