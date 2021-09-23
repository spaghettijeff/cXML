CC = gcc
CFLAGS = -Wall -g

build: test.o cxml.o
	$(CC) test.o cxml.o $(CFLAGS) -o build

test.o: test.c cxml.c cxml.h
	$(CC) $(CFLAGS) -c test.c

cxml.o: cxml.c cxml.h
	$(CC) $(CFLAGS) -c cxml.c

clean:
	rm *.o build
