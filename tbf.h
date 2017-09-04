#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
	time_t timestamp;				/* Last update */
	unsigned long long int count;	/* Available tokens */
	unsigned short int burst;		/* Max number of tokens */
	unsigned short int rate;		/* Rate of replenishment */
	unsigned short int mark;		/* Whether last op was limited */
} tbf;

int tbf_rl(tbf * rl);
