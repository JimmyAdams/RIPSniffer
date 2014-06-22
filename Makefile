CC=g++
CFLAGS=-W -Wall -Wextra -pedantic -O2
LDFLAGS_SNIFF=-lpcap
LDFLAGS_RESPONSE=
LDFLAGS_REQUEST=
PROG_SNIFF=myripsniffer
PROG_RESPONSE=myripresponse
PROG_REQUEST=myriprequest

.PHONY: all tar clean

all: $(PROG_SNIFF) $(PROG_RESPONSE) $(PROG_REQUEST)

$(PROG_SNIFF): myripsniffer.o net.o
	$(CC) -o $@ myripsniffer.o net.o $(LDFLAGS_SNIFF)

$(PROG_RESPONSE): myripresponse.o net.o
	$(CC) -o $@ myripresponse.o net.o $(LDFLAGS_RESPONSE)

$(PROG_REQUEST): myriprequest.o net.o
	$(CC) -o $@ myriprequest.o net.o $(LDFLAGS_REQUEST)

myripsniffer.o: myripsniffer.cc
	$(CC) $(CFLAGS) -c -o $@ myripsniffer.cc

myripresponse.o: myripresponse.cc
	$(CC) $(CFLAGS) -c -o $@ myripresponse.cc

myriprequest.o: myriprequest.cc
	$(CC) $(CFLAGS) -c -o $@ myriprequest.cc

net.o: net.cc net.h
	$(CC) $(CFLAGS) -c -o $@ net.cc

clean:
	rm -f *.o

