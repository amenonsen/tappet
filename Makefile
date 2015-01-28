NACLLIB = nacl/build/lib
NACLINC = nacl/build/include

CFLAGS = -std=c99 -Wall -pedantic -D_POSIX_SOURCE -D_POSIX_C_SOURCE=199309 -I$(NACLINC) $(OPTIM)
LDLIBS = -lrt

OBJS = crypt.o util.o
EXEC = tappet tappet-keygen nacl-test
NACL = $(NACLLIB)/libnacl.a $(NACLLIB)/randombytes.o

all: $(NACL) tappet tappet-keygen

$(EXEC): $(OBJS) $(NACL)

# Running nacl/do will unconditionally build NaCl in
# nacl/build/$hostname, with the library itself in lib/$abi and the
# include files in include/$abi, where $abi is the output of bin/okabi.
# Since it's difficult to convince Make to expand a variable assignment
# such as $(shell nacl/build/$(HOSTNAME)/bin/okabi) only after building
# a target, we just create links in nacl/build/{lib,include}.

$(NACL):
	cd nacl && ./do && ./link

clean:
	rm -f $(OBJS) $(EXEC)
