rm=/bin/rm -f
CC=gcc
CFLAGS= -std=c99 -g

all: client

client:  client.c
	$(CC) $(CFLAGS) -o client client.c -lssl -lcrypto

clean:
	$(rm) *.o client *~

