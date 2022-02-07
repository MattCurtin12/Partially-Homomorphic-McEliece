
#define WEIGHT_M 8                             //the error correcting weight of messages
#define SYS_N_ORIG 3488                         //N parameter for full message
#define SYS_T_ORIG 64                           //Weight of full message
#define SYS_N_ENC (SYS_N_ORIG - WEIGHT_M)         //N parameter for half message for making e1 and e2
#define SYS_T_ENC (SYS_T_ORIG / 2 - WEIGHT_M)	//Weight of e1 and e2


void gen_e(unsigned char* e);
void syndrome(unsigned char* s, const unsigned char* pk, unsigned char *e);
