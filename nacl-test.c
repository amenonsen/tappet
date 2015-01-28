#include "tappet.h"

void dump(char *prefix, unsigned char *buf, int len)
{
    int i = 0;

    printf("%s: ", prefix);
    while (i < len) {
        printf("%02x ", buf[i]);
        i++;
    }
    printf("\n");
}

int main()
{
    int i;
    unsigned char oursk[KEYBYTES];
    unsigned char ourpk[KEYBYTES];
    unsigned char theirpk[KEYBYTES];
    unsigned char theirsk[KEYBYTES];
    unsigned char k[crypto_box_BEFORENMBYTES];
    unsigned char kk[crypto_box_BEFORENMBYTES];
    unsigned char n[crypto_box_NONCEBYTES];
    unsigned char m[crypto_box_ZEROBYTES+16];
    unsigned char mm[crypto_box_ZEROBYTES+16];
    unsigned char c[crypto_box_ZEROBYTES+16];
    unsigned int mlen = crypto_box_ZEROBYTES+16;

    crypto_box_keypair(ourpk,oursk);
    crypto_box_keypair(theirpk,theirsk);

    dump("oursk", oursk, KEYBYTES);
    dump("ourpk", ourpk, KEYBYTES);
    dump("theirpk", theirpk, KEYBYTES);
    dump("theirsk", theirsk, KEYBYTES);

    i = crypto_box_beforenm(k, theirpk, oursk);
    printf("crypto_box_beforenm(k) = %d\n", i);
    dump("k", k, crypto_box_BEFORENMBYTES);

    i = crypto_box_beforenm(kk, ourpk, theirsk);
    printf("crypto_box_beforenm(kk) = %d\n", i);
    dump("kk", kk, crypto_box_BEFORENMBYTES);

    i = 0;
    while (i < crypto_box_NONCEBYTES) {
        n[i] = 0xFF;
        i++;
    }
    dump("n", n, crypto_box_NONCEBYTES);

    generate_nonce(0, n);
    dump("n", n, crypto_box_NONCEBYTES);

    i = 0;
    while (i < 123140) {
        update_nonce(0, n);
        i++;
    }
    dump("n'", n, crypto_box_NONCEBYTES);

    i = 0;
    while (i < 35983224) {
        update_nonce(0, n);
        i++;
    }
    dump("n''", n, crypto_box_NONCEBYTES);

    memset(c, 0, crypto_box_ZEROBYTES+16);
    memset(m, 0, crypto_box_ZEROBYTES+16);
    memset(mm, 0, crypto_box_ZEROBYTES+16);

    i = 0;
    while (i < 16) {
        mm[crypto_box_ZEROBYTES+i] = 0;
        m[crypto_box_ZEROBYTES+i] = 'a'+i;
        i++;
    }

    i = crypto_box(c, m, mlen, n, theirpk, oursk);
    printf("crypto_box = %d\n", i);

    dump("m", m, mlen);
    dump("c", c, mlen);

    i = crypto_box_afternm(c, m, mlen, n, k);
    printf("crypto_box_afternm = %d\n", i);

    dump("m", m, mlen);
    dump("c", c, mlen);

    i = crypto_box_open(mm, c, mlen, n, ourpk, theirsk);
    printf("crypto_box_open = %d\n", i);

    dump("mm", mm, mlen);

    i = crypto_box_open_afternm(mm, c, mlen, n, kk);
    printf("crypto_box_open_afternm = %d\n", i);

    dump("mm", mm, mlen);

    return 0;
}
