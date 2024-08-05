liar: *.c *.h
	gcc -g liar.c -o liar

test: test.c
	gcc -g test.c -o test

clean:
	rm -f liar

all: liar test

.PHONY: clean all
