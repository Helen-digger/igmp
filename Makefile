CC= gcc -std=c99
PRF :=$(pwd)
CFLAGS   = -Wall -Werror
CLSRC = igmp_client.c protocol.c timers.c
#SOURC:=$( find $DIR -name '*.c')
all:
	$(CC) $(CFLAGS) -o igmp_client $(CLSRC) -dD
clean:
	rm -f igmp_client gen_igmp *.o *.a *.so 
