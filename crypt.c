#include "tappet.h"

#include <time.h>

extern void randombytes(unsigned char *buf, unsigned long long len);

/*
 * Generates a nonce with the given prefix into the given buffer.
 */

void generate_nonce(uint32_t prefix,
                    unsigned char nonce[NONCEBYTES])
{
    /*
     * This is what naclcrypto-20090310.pdf has to say about nonce
     * generation:
     *
     * «Alice and Bob assign to each packet a nonce n ∈ {0,1,…,255}24: a
     * unique message number that will never be reused for other packets
     * exchanged between Alice and Bob. For example, the nonce can be
     * chosen as a simple counter: 0 for Alice’s first packet, 1 for
     * Bob’s first packet, 2 for Alice’s second packet, 3 for Bob’s
     * second packet, 4 for Alice’s third packet, 5 for Bob’s third
     * packet, etc. Choosing the nonce as a counter followed by (e.g.)
     * 32 random bits helps protect some protocols against
     * denial-of-service attacks. In many applications it is better to
     * increase the counter to, e.g., the number of nanoseconds that
     * have passed since a standard epoch in the local clock, so that
     * the current value of the counter does not leak the traffic rate.
     * Note that “increase” does not mean “increase or decrease”; if the
     * clock jumps backwards, the counter must continue to increase.»
     *
     * We use a four-byte prefix, twelve bytes initialised at startup
     * with random data, and an eight-byte nanosecond counter. We write
     * the prefix and counter in network byte order, because the nonce
     * is later compared with memcmp().
     */

    nonce[0] = prefix >> 24;
    nonce[1] = prefix >> 16;
    nonce[2] = prefix >> 8;
    nonce[3] = prefix;

    randombytes(nonce+4, 12);

    update_nonce(nonce);
}


/*
 * Updates the counter portion of the given nonce.
 */

void update_nonce(unsigned char nonce[NONCEBYTES])
{
    int i;
    uint64_t n;
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0) {
        fprintf(stderr, "clock_gettime() failed: %s\n", strerror(errno));
        exit(-1);
    }

    n = ((uint64_t)tp.tv_sec) * 1000*1000*1000 + tp.tv_nsec;

    i = 0;
    while (i < 8) {
        nonce[NONCEBYTES-i-1] = n & 0xFF;
        n >>= 8;
        i++;
    }
}


/*
 * Decrypts the contents of ctbuf and writes the result to ptbuf.
 * Returns the number of characters in ptbuf on success and -1 on
 * failure.
 */

int decrypt(unsigned char k[crypto_box_BEFORENMBYTES],
            unsigned char nonce[NONCEBYTES],
            unsigned char *ctbuf, int ctlen,
            unsigned char *ptbuf)
{
    if (crypto_box_open_afternm(ptbuf, ctbuf, ctlen, nonce, k) < 0)
        return -1;

    return ctlen;
}


/*
 * Encrypts the contents of ptbuf and writes the result to ctbuf.
 * Returns the number of characters in ctbuf on success and -1 on
 * failure.
 */

int encrypt(unsigned char k[crypto_box_BEFORENMBYTES],
            unsigned char nonce[NONCEBYTES],
            unsigned char *ptbuf, int ptlen,
            unsigned char *ctbuf)
{
    if (crypto_box_afternm(ctbuf, ptbuf, ptlen, nonce, k) < 0)
        return -1;

    return ptlen;
}
