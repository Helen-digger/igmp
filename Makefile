CC= gcc -std=c99
PRF :=$(pwd)
CFLAGS   = -Wall -Werror
CLSRC = igmp_client.c protocol.c
#SOURC:=$( find $DIR -name '*.c')
all:
	$(CC) $(CFLAGS) -o igmp_client $(CLSRC)  -lpthread -dD
	$(CC) $(CFLAGS) -o gen_igmp gen_igmp.c protocol.c -DIGMP_GEN
clean:
	rm -f igmp_client gen_igmp *.o *.a *.so 
