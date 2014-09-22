/*
 * Abhijit Menon-Sen <ams@toroid.org>
 * 2014-09-20
 */

#include "tappet.h"
#include "tweetnacl.h"

int tunnel(int role, const struct sockaddr *server, socklen_t srvlen,
           int tap, int udp, unsigned char oursk[KEYBYTES],
           unsigned char theirpk[KEYBYTES]);

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
    unsigned char buf[65536];
    unsigned char k[crypto_box_BEFORENMBYTES];
    struct sockaddr_storage peeraddr;
    struct sockaddr *peer;
    socklen_t peerlen;

    /*
     * Precompute a shared secret from the two keys.
     */

    crypto_box_beforenm(k, oursk, theirpk);

    /*
     * The client always knows where to send UDP packets, but the server
     * has to wait until it receives a valid packet from the client. To
     * keep the code simple, both sides always sendto() their peer. The
     * client connect()s on the socket, but the server doesn't (so that
     * it receives packets from a client whose IP address has changed).
     */

    peer = (struct sockaddr *) &peeraddr;
    peerlen = sizeof(peeraddr);
    memset(peer, 0, peerlen);

    if (role == 0) {
        memcpy(peer, server, srvlen);
        peerlen = srvlen;
    }

    /*
     * We want to do non-blocking reads on the TAP fd to drain the queue
     * on every read notification, but we'd prefer to do blocking writes
     * rather than buffering. It's cheap to set and clear O_NONBLOCK, so
     * that's what we do.
     *
     * We don't have to do this for the UDP socket, because we can just
     * use recvfrom(…, MSG_DONTWAIT) and sendto without MSG_DONTWAIT to
     * get exactly the semantics we need.
     */

    set_blocking(tap, 0);

    /*
     * Now both sides loop waiting for readability events on their fds.
     */

    maxfd = tap > udp ? tap : udp;

    while (1) {
        fd_set r;
        int n, err;

        FD_ZERO(&r);
        FD_SET(udp, &r);

        /*
         * Don't listen for TAP packets until we know where to send them
         * (which the client always does).
         */

        if (peer->sa_family != 0)
            FD_SET(tap, &r);

        err = select(maxfd+1, &r, NULL, NULL, NULL);
        if (err < 0)
            return err;

        /*
         * We read a complete packet from the UDP socket and try to
         * decrypt it. If that fails, we discard the packet silently.
         * Otherwise we write the decrypted result to the TAP fd.
         */

        if (FD_ISSET(udp, &r)) {
            while (1) {
                n = recvfrom(udp, (void *) buf, 65536, MSG_DONTWAIT|MSG_TRUNC,
                             peer, &peerlen);

                /*
                 * Either there's nothing to read, or something broke.
                 */

                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;

                    fprintf(stderr, "Error reading from UDP socket: %s\n",
                            strerror(errno));
                    return n;
                }

                /*
                 * We complain at length about the "connection" closing
                 * or receiving oversized packets, but we ultimately
                 * ignore them and carry on.
                 */

                if (n == 0 || n > 65536) {
                    char peeraddr[256];

                    describe_sockaddr(peer, peeraddr, 256);

                    if (n == 0) {
                        fprintf(stderr, "Orderly shutdown from %s; ignoring\n",
                                peeraddr);
                    }
                    else {
                        fprintf(stderr, "Received oversize (%d bytes) packet from "
                                "%s; ignoring\n", n, peeraddr);
                    }

                    continue;
                }

                /*
                 * We have a complete packet. Write it to the TAP device
                 * (without any decryption yet).
                 */

                if (tap_write(tap, buf, n) < 0)
                    return -1;
            }
        }

        /*
         * We read ethernet frames from the TAP device in much the same
         * way as above, except that we use read and sendto instead of
         * recvfrom and write.
         */

        if (FD_ISSET(tap, &r)) {
            while (1) {
                n = read(tap, buf, 65536);

                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;

                    fprintf(stderr, "Error reading from TAP device: %s\n",
                            strerror(errno));
                    return n;
                }

                if (n == 0) {
                    fprintf(stderr, "TAP fd closed; exiting\n");
                    return -1;
                }

                if (udp_write(udp, buf, n, peer, peerlen) < 0)
                    return -1;
            }
        }
    }
}
