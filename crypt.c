#include "tappet.h"
#include "tweetnacl.h"

extern void randombytes(unsigned char *buf, unsigned long long len);

/*
 * Generates a nonce based on our role and stores it in buf, which is
 * assumed to point to crypto_box_NONCEBYTES of usable storage.
 */

void generate_nonce(int role, unsigned char *buf)
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
    while (i < crypto_box_NONCEBYTES-4-1)
        buf[i++] = 0;
    buf[i++] = role;
    randombytes(buf+i, 4);
}


/*
 * Decrypts the contents of ctbuf and writes the result to ptbuf.
 * Returns the number of characters in ptbuf on success and -1 on
 * failure.
 */

int decrypt(unsigned char *ctbuf, int ctlen,
            unsigned char *ptbuf, int ptlen)
{
    if (ctlen > ptlen)
        return -1;

    memcpy(ptbuf, ctbuf, ctlen);
    return ctlen;
}


/*
 * Encrypts the contents of ptbuf and writes the result to ctbuf.
 * Returns the number of characters in ctbuf on success and -1 on
 * failure.
 */

int encrypt(unsigned char *ptbuf, int ptlen,
            unsigned char *ctbuf, int ctlen)
{
    if (ptlen > ctlen)
        return -1;

    memcpy(ctbuf, ptbuf, ptlen);
    return ptlen;
}
