CFLAGS = -std=c99 -pedantic

NACL = tweetnacl.c devurandom.c

all: tappet tappet-keygen

tappet: $(NACL)

tappet-keygen: $(NACL)

clean:
	rm -f tappet tappet-keygen
