CFLAGS = $(OPTIM) -D_POSIX_SOURCE -std=c99 -pedantic

SOURCES = util.c tweetnacl.c devurandom.c

all: tappet tappet-keygen

tappet: $(SOURCES)

tappet-keygen: $(SOURCES)

clean:
	rm -f tappet tappet-keygen
