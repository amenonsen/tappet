#include "tappet.h"

#include <limits.h>

extern void randombytes(unsigned char *buf, unsigned long long len);

/*
 * Generates a nonce based on our role into the given buffer.
 */

void generate_nonce(int role, unsigned char nonce[NONCEBYTES])
{
    int i;

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
     * For now, we generate a twenty-byte counter starting at 0 (for the
     * client) and 1 (for the server) followed by 32 random bits.
     */

    i = 0;
    while (i < NONCEBYTES-4-1)
        nonce[i++] = 0;
    nonce[i++] = role;
    randombytes(nonce+i, 4);
}


/*
 * Increments the given nonce as appropriate for the role.
 */

void increment_nonce(int role, unsigned char nonce[NONCEBYTES])
{
    /*
     * For now, we just increment the twenty-byte counter part of the
     * nonce by 2, no matter what the role.
     */

    int inc = 2;
    int idx = 20;
    unsigned char *d;

    do {
        d = nonce + --idx;

        if (*d+inc < 255) {
            *d += inc;
            return;
        }

        inc = 1;
    }
    while (idx > 0);

    /*
     * If we haven't returned by now, then we overflowed the counter,
     * which would be 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF on the
     * server, and 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE on the
     * client. We can't even generate a new nonce, because it won't be
     * larger than the old one (since the randomness is in the least
     * significant portion of the twenty-four bytes).
     *
     * OH NO! THERE'S NOTHING WE CAN DO!
     */

    fprintf(stderr, "Goodbye, cruel world.\n");
    exit(-INT_MAX);
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
