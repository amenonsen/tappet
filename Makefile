CFLAGS = -Wall $(OPTIM) -D_POSIX_SOURCE -D_POSIX_C_SOURCE=199309 -std=c99 -pedantic -lrt

SOURCES = crypt.c util.c tweetnacl.c devurandom.c

all: tappet tappet-keygen

tappet: $(SOURCES)

tappet-keygen: $(SOURCES)

nacl-test: $(SOURCES)

clean:
	rm -f tappet tappet-keygen nacl-test
