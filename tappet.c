/*
 * Abhijit Menon-Sen <ams@toroid.org>
 * 2014-09-20
 */

#include "tappet.h"

int tunnel(int role, const struct sockaddr *server, socklen_t srvlen,
           int tap, int udp, unsigned char oursk[KEYBYTES],
           unsigned char theirpk[KEYBYTES]);
int send_keepalive(int role, int udp, const struct sockaddr *peer,
                   socklen_t peerlen, unsigned char nonce[NONCEBYTES],
                   unsigned char k[crypto_box_BEFORENMBYTES]);

int main(int argc, char *argv[])
{
    int tap, udp, role;
    unsigned char oursk[KEYBYTES];
    unsigned char theirpk[KEYBYTES];
    struct sockaddr *server;
    socklen_t srvlen;

    /*
     * We require exactly five arguments: the interface name, the name
     * of a file that contains our private key, the name of a file that
     * contains the other side's public key, and the address and port of
     * the server side.
     */

    if (argc < 6) {
        fprintf(stderr, "Usage: tappet ifaceN /our/privkey /their/pubkey address port [-l]\n");
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

    tap = tap_attach(argv[1]);
    if (tap < 0)
        return -1;

    /*
     * Load our own secret key and the other side's public key from the
     * given files. We assume that the keys have been competently
     * generated.
     */

    if (read_key(argv[2], oursk) < 0)
        return -1;

    if (read_key(argv[3], theirpk) < 0)
        return -1;

    /*
     * The next two arguments are an address (which may be either IPv4
     * or IPv6, but not a hostname) and a port number, so we convert it
     * into a sockaddr.
     */

    if (get_sockaddr(argv[4], argv[5], &server, &srvlen) < 0)
        return -1;

    /*
     * Now we create a UDP socket. If there's a remaining -l, we'll bind
     * the server sockaddr to it, otherwise we'll connect to it.
     */

    role = argc > 6 && strcmp(argv[6], "-l") == 0;
    udp = udp_socket(role, server, srvlen);
    if (udp < 0)
        return -1;

    /*
     * Now we start the encrypted tunnel and let it run.
     */

    return tunnel(role, server, srvlen, tap, udp, oursk, theirpk);
}

/*
 * Stays in a loop reading packets from both the TAP device and the UDP
 * socket. Encrypts and forwards packets from TAP→UDP, and decrypts and
 * forwards in the other direction.
 */

int tunnel(int role, const struct sockaddr *server, socklen_t srvlen,
           int tap, int udp, unsigned char oursk[KEYBYTES],
           unsigned char theirpk[KEYBYTES])
{
    int maxfd;
    unsigned char ptbuf[2048];
    unsigned char ctbuf[2048];
    unsigned char ournonce[NONCEBYTES];
    unsigned char theirnonce[NONCEBYTES];
    unsigned char k[crypto_box_BEFORENMBYTES];
    struct sockaddr_storage peeraddr;
    struct sockaddr *peer;
    socklen_t peerlen;

    /*
     * Generate a nonce based on our role, zero bytes that should be
     * zero, and precompute a shared secret from the two keys.
     */

    generate_nonce(role, ournonce);
    memset(ptbuf, 0, ZEROBYTES);
    memset(theirnonce, 0, sizeof(theirnonce));
    crypto_box_beforenm(k, theirpk, oursk);

    /*
     * Each side has UDP packets to sendto() its peer: for the client,
     * it's the server; for the server, it's the result of recvfrom().
     * The client connect()s on the socket, but the server doesn't (so
     * that it can receive packets from a client whose IP address has
     * changed).
     */

    peer = (struct sockaddr *) &peeraddr;
    peerlen = sizeof(peeraddr);
    memset(peer, 0, peerlen);

    if (role == 0) {
        memcpy(peer, server, srvlen);
        peerlen = srvlen;
    }

    /*
     * Now both sides loop waiting for readability events on their fds.
     */

    maxfd = tap > udp ? tap : udp;

    while (1) {
        fd_set r;
        int n, nfds;
        struct timeval tv;

        tv.tv_sec = 75;
        tv.tv_usec = 0;

        FD_ZERO(&r);
        FD_SET(udp, &r);

        /*
         * Don't listen for TAP packets unless we know where to send
         * them (which the client always does).
         */

        if (peer->sa_family != 0)
            FD_SET(tap, &r);

        nfds = select(maxfd+1, &r, NULL, NULL, &tv);
        if (nfds < 0) {
            fprintf(stderr, "select() failed: %s\n", strerror(errno));
            return nfds;
        }

        /*
         * We read a packet from the UDP socket and try to decrypt it.
         * If that fails, we discard the packet silently. Otherwise we
         * write the decrypted result to the TAP device.
         */

        if (FD_ISSET(udp, &r)) {
            while (1) {
                unsigned char lastnonce[NONCEBYTES];

                memcpy(lastnonce, theirnonce, sizeof(theirnonce));

                n = udp_read(udp, theirnonce, ctbuf, sizeof(ctbuf), peer, &peerlen);

                if (n == 0)
                    break;

                if (n > 0 && memcmp(lastnonce, theirnonce, NONCEBYTES) >= 0)
                    n = -1;
                if (n > 0)
                    n = decrypt(k, theirnonce, ctbuf, n, ptbuf);

                /*
                 * If anything goes wrong on the server, we forget the
                 * peer so that we don't try to send any packets to it.
                 */

                if (role == 1 && n < 0) {
                    memset(&peeraddr, 0, sizeof(peeraddr));
                    memset(theirnonce, 0, sizeof(theirnonce));
                }

                if (n < -2)
                    return n;

                /*
                 * Either there was an error we want to ignore (n == -1)
                 * or the decrypted packet wasn't long enough to be a
                 * valid ethernet frame. Since decryption succeeded,
                 * we treat it as a keepalive.
                 */

                if (n < 64)
                    continue;

                /*
                 * Write the decrypted ethernet frame to the TAP device.
                 */

                if (tap_write(tap, ptbuf+ZEROBYTES, n-ZEROBYTES) < 0)
                    return -1;
            }
        }

        /*
         * Similarly, we read ethernet frames from the TAP device and
         * write them to the UDP socket after encryption.
         */

        if (FD_ISSET(tap, &r)) {
            while (1) {
                n = tap_read(tap, ptbuf+ZEROBYTES, sizeof(ptbuf)-ZEROBYTES);
                if (n > 0) {
                    increment_nonce(role, ournonce);
                    n = encrypt(k, ournonce, ptbuf, n+ZEROBYTES, ctbuf);
                }

                if (n == 0)
                    break;

                if (n < 0)
                    return n;

                if (udp_write(udp, ournonce, ctbuf, n, peer, peerlen) < 0)
                    return -1;
            }
        }

        /*
         * If 75 seconds have elapsed on the client without any traffic,
         * we send a keepalive packet to the server so that it remembers
         * the client even after an address change.
         */

        if (nfds == 0 && role == 0) {
            increment_nonce(role, ournonce);
            if (send_keepalive(role, udp, peer, peerlen, ournonce, k) < 0)
                return -1;
        }
    }
}


/*
 * Sends an encrypted keepalive packet to the peer. Uses the nonce
 * without incrementing it. Returns 0 on success, -1 on failure.
 */

int send_keepalive(int role, int udp, const struct sockaddr *peer,
                   socklen_t peerlen, unsigned char nonce[NONCEBYTES],
                   unsigned char k[crypto_box_BEFORENMBYTES])
{
    int n;
    unsigned char p[ZEROBYTES+1];
    unsigned char c[ZEROBYTES+1];

    memset(p, 0, ZEROBYTES);
    p[ZEROBYTES] = 0xFF;

    n = encrypt(k, nonce, p, 1+ZEROBYTES, c);

    if (udp_write(udp, nonce, c, n, peer, peerlen) < 0)
        return -1;

    return 0;
}
