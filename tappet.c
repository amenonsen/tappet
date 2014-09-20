/*
 * Abhijit Menon-Sen <ams@toroid.org>
 * Public domain; 2014-09-20
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "tweetnacl.h"

int tap_attach(const char *name);
int read_pubkey(const char *name, unsigned char pk[crypto_box_PUBLICKEYBYTES]);
int read_keypair(const char *name, unsigned char sk[crypto_box_SECRETKEYBYTES],
                 unsigned char pk[crypto_box_PUBLICKEYBYTES]);

int main(int argc, char *argv[])
{
    int fd;
    unsigned char oursk[crypto_box_SECRETKEYBYTES];
    unsigned char ourpk[crypto_box_PUBLICKEYBYTES];
    unsigned char theirpk[crypto_box_PUBLICKEYBYTES];

    /*
     * We require exactly five arguments: the interface name, the name
     * of a file containing our keypair, the name of a file containing
     * the other side's public key, and the address and port of the
     * server side.
     */

    if (argc < 6) {
        fprintf(stderr, "Usage: tappet ifaceN /our/keypair /their/pubkey address port\n");
        return -1;
    }

    /*
     * Attach to the given TAP interface as an ordinary user (so that we
     * don't create it by mistake; we assume it's already configured).
     */

    if (geteuid() == 0) {
        fprintf(stderr, "Please run tappet as an ordinary user\n");
        return -1;
    }

    fd = tap_attach(argv[1]);
    if (fd < 0)
        return -1;

    /*
     * Load our own keypair and the other side's public key from the
     * given files. We assume that the keys have been competently
     * generated.
     */

    if (read_keypair(argv[2], oursk, ourpk) < 0)
        return -1;

    if (read_pubkey(argv[3], theirpk) < 0)
        return -1;

    /* … */

    return 0;
}

/*
 * Attaches to the TAP interface with the given name and returns an fd
 * (as described in linux/Documentation/networking/tuntap.txt).
 *
 * If this code is run as root, it will create the interface if it does
 * not exist. (It would be nice to report a more useful error when the
 * interface doesn't exist, but TUNGETIFF works on the attached fd; we
 * have only an interface name.)
 */

int tap_attach(const char *name)
{
    int n, fd;
    struct ifreq ifr;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Couldn't open /dev/net/tun: %s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_flags = IFF_TAP;

    n = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (n < 0) {
        fprintf(stderr, "Couldn't attach to %s: %s\n", name, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}


/*
 * Reads two hex characters from the source pointer and writes a single
 * byte to the destination pointer. Returns -1 if any characters are not
 * valid hex.
 */

int decode_hex(char *s, char *t)
{
    char a, b;

    a = *s | 0x20;
    if (a >= '0' && a <= '9')
        a -= '0';
    else if (a >= 'a' && a <= 'f')
        a -= 'a';
    else
        return -1;

    b = *(s+1) | 0x20;
    if (b >= '0' && b <= '9')
        b -= '0';
    else if (b >= 'a' && b <= 'f')
        b -= 'a';
    else
        return -1;

    *t = a << 4 | b;
    return 0;
}


/*
 * Tries to read 64 hex bytes followed by a newline from the given file
 * handle and write the decoded 32-byte key to the given array. Returns
 * 0 on success, -1 on failure. Does not print any error message.
 *
 * Note that this won't work if crypto_box_SECRETKEYBYTES ever differs
 * from crypto_box_PUBLICKEYBYTES, hence the hardcoded 32.
 */

int read_hexkey(FILE *f, unsigned char key[32])
{
    char line[32*2+2];
    char *p, *q;

    if (fgets(line, 66, f) == NULL || strlen(line) != 65 || line[64] != '\n')
        return -1;

    p = line;
    q = (char *) key;

    while (*p != '\n') {
        if (decode_hex(p, q) < 0)
            return -1;
        p += 2;
        q++;
    }

    return 0;
}


/*
 * Reads secret and public keys in hex format from the first two lines
 * of the given file into the sk and pk arrays. Returns -1 on any error,
 * or 0 on success.
 */

int read_keypair(const char *name,
                 unsigned char sk[crypto_box_SECRETKEYBYTES],
                 unsigned char pk[crypto_box_PUBLICKEYBYTES])
{
    FILE *f;

    f = fopen(name, "r");
    if (!f) {
        fprintf(stderr, "Couldn't open keypair file %s: %s\n", name, strerror(errno));
        return -1;
    }

    if (read_hexkey(f, sk) < 0) {
        fprintf(stderr, "Couldn't read private key (64 hex characters) from %s\n", name);
        return -1;
    }

    if (read_hexkey(f, pk) < 0) {
        fprintf(stderr, "Couldn't read public key (64 hex characters) from %s\n", name);
        return -1;
    }

    (void) fclose(f);
    return 0;
}


/*
 * Reads a public key in hex format from the first line of the given
 * file into the pk array. Returns -1 on any error, or 0 on success.
 */

int read_pubkey(const char *name, unsigned char pk[crypto_box_PUBLICKEYBYTES])
{
    FILE *f;

    f = fopen(name, "r");
    if (!f) {
        fprintf(stderr, "Couldn't open public key file %s: %s\n", name, strerror(errno));
        return -1;
    }

    if (read_hexkey(f, pk) < 0) {
        fprintf(stderr, "Couldn't read public key (64 hex characters) from %s\n", name);
        return -1;
    }

    (void) fclose(f);
    return 0;
}
