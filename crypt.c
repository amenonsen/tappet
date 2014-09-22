#include "tappet.h"

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
