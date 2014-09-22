CFLAGS = -Wall $(OPTIM) -D_POSIX_SOURCE -std=c11 -pedantic

SOURCES = crypt.c util.c tweetnacl.c devurandom.c

all: tappet tappet-keygen

tappet: $(SOURCES)

tappet-keygen: $(SOURCES)

clean:
	rm -f tappet tappet-keygen
