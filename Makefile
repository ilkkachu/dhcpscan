LIBS=-lpcap -lnet
CC=gcc
CFLAGS=-Wall -O2 -g -std=c99

all: dhcpscan

dhcpscan: dhcpscan.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	
clean:
	-rm dhcpscan 
