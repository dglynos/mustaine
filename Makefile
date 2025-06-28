all: mustained mustaine-thrash

mustained: mustained.c chunked.o mime.o
	gcc -Wall -g -ggdb -o $@ $^ -lssl -lcrypto -lmagic -pthread

mustaine-thrash: mustaine-thrash.c
	gcc -Wall -g -ggdb -o $@ $< -lcurl

chunked.o: chunked.c chunked.h
	gcc -Wall -g -ggdb -c $< -pthread

mime.o: mime.c mime.h
	gcc -Wall -g -ggdb -c $< -pthread

clean:
	rm -f mustained mustaine-thrash *.o

.PHONY: all clean
