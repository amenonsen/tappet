VERSION = $(shell git describe)

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

deb: $(EXEC)
	fpm -s dir -t deb -n tappet -v $(VERSION) \
		--after-install pkg/after-install.sh \
		--after-remove pkg/after-remove.sh \
		./tappet=/usr/sbin/tappet \
		./tappet-keygen=/usr/sbin/tappet-keygen \
		./pkg/tappet@.service=/lib/systemd/system/tappet@.service

clean:
	rm -f $(OBJS) $(EXEC)
