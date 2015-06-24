
all: coin sample

coin: duping.o
	gcc -o coin coin.c duping.o

sample:
	gcc -o sample sample.c

duping.o:
	gcc -c duping.S


clean:
	rm -rf *.o coin sample *~

