CFLAGS = -funsigned-char -Wall -Wno-implicit-function-declaration -std=c99 -pedantic

tappet: tappet.c tweetnacl.c devurandom.c

clean:
	rm -f tappet
