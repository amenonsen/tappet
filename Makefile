HOSTNAME = $(shell hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]')

NACLDIR = nacl/build/$(HOSTNAME)
NACLABI = $(shell $(NACLDIR)/bin/okabi)
NACLINC = $(NACLDIR)/include/$(NACLABI)
NACLLIB = $(NACLDIR)/lib/$(NACLABI)

CFLAGS = -std=c99 -Wall -pedantic -D_POSIX_SOURCE -D_POSIX_C_SOURCE=199309 -I$(NACLINC) $(OPTIM)
LDLIBS = -lrt

OBJS = crypt.o util.o
EXEC = tappet tappet-keygen nacl-test
NACL = $(NACLLIB)/libnacl.a $(NACLLIB)/randombytes.o

all: tappet tappet-keygen

$(EXEC): $(OBJS) $(NACL)

$(NACL):
	cd nacl && ./do

clean:
	rm -f $(OBJS) $(EXEC)
