#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "tweetnacl.h"

int main(int argc, char *argv[])
{
    int i, fd;
    FILE *key, *pub;
    char f[128];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];

    if (argc < 2) {
        fprintf(stderr, "Usage: tappet-keygen <keyname>\n");
        return -1;
    }

    strncpy(f, argv[1], 123);
    strcat(f, ".key");
    fd = open(f, O_CREAT|O_EXCL|O_WRONLY, 0600);
    if (fd > 0)
        key = fdopen(fd, "w");
    if (fd < 0 || !key) {
        fprintf(stderr, "Can't open %s: %s\n", f, strerror(errno));
        return -1;
    }

    strncpy(f, argv[1], 123);
    strcat(f, ".pub");
    fd = open(f, O_CREAT|O_EXCL|O_WRONLY, 0644);
    if (fd > 0)
        pub = fdopen(fd, "w");
    if (fd < 0 || !pub) {
        fprintf(stderr, "Can't open %s: %s\n", f, strerror(errno));
        return -1;
    }

    crypto_box_keypair(sk, pk);

    for(i = 0; i < 32; i++)
        fprintf(key, "%02x", sk[i]);
    fprintf(key, "\n");

    for(i = 0; i < 32; i++)
        fprintf(pub, "%02x", pk[i]);
    fprintf(pub, "\n");

    (void) fclose(key);
    (void) fclose(pub);
    return 0;
}
