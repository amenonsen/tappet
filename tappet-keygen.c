/*
 * Abhijit Menon-Sen <ams@toroid.org>
 * Public domain; 2014-09-20
 */

#include <stdio.h>

#include "tweetnacl.h"

int main()
{
    int i;
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];

    crypto_box_keypair(sk, pk);

    for(i = 0; i < 32; i++)
        printf("%02x", sk[i]);
    printf("\n");

    for(i = 0; i < 32; i++)
        printf("%02x", pk[i]);
    printf("\n");

    return 0;
}
