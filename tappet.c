/*
 * Abhijit Menon-Sen <ams@toroid.org>
 * Public domain; 2014-09-20
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>

#include "tweetnacl.h"

static struct sockaddr_in in_addr;
static struct sockaddr_in6 in6_addr;

#define KEYBYTES 32

int tap_attach(const char *name);
int read_key(const char *name, unsigned char key[KEYBYTES]);
int get_sockaddr(const char *address, const char *sport, struct sockaddr **addr);
int udp_socket(const struct sockaddr *server, int role);
int tunnel(int role, const struct sockaddr *server, int tap,
           int udp, unsigned char oursk[KEYBYTES],
           unsigned char theirpk[KEYBYTES]);

int main(int argc, char *argv[])
{
    int tap, udp, role;
    unsigned char oursk[KEYBYTES];
    unsigned char theirpk[KEYBYTES];
    struct sockaddr *server;

    /*
     * We require exactly five arguments: the interface name, the name
     * of a file containing our keypair, the name of a file containing
     * the other side's public key, and the address and port of the
     * server side.
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
     * into a sockaddr for later use.
     */

    if (get_sockaddr(argv[4], argv[5], &server) < 0)
        return -1;

    /*
     * Now we create a UDP socket. If there's a remaining -l, we'll bind
     * the server sockaddr to it, otherwise we'll connect to it.
     */

    role = argc > 6 && strcmp(argv[6], "-l") == 0;
    udp = udp_socket(server, role);
    if (udp < 0)
        return -1;

    /*
     * Now we start the encrypted tunnel and let it run.
     */

    return tunnel(role, server, tap, udp, oursk, theirpk);
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
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

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
 * Decodes a key in hex format from the first line of the given file
 * into the key array. Returns -1 on any error, or 0 on success.
 */

int read_key(const char *name, unsigned char key[KEYBYTES])
{
    FILE *f;

    f = fopen(name, "r");
    if (!f) {
        fprintf(stderr, "Couldn't open key file %s: %s\n", name, strerror(errno));
        return -1;
    }

    if (read_hexkey(f, key) < 0) {
        fprintf(stderr, "Couldn't read key (64 hex characters) from %s\n", name);
        return -1;
    }

    (void) fclose(f);
    return 0;
}


/*
 * Takes two command line arguments and tries to parse them as an IP
 * (v4 or v6) address and a port number. If it succeeds, it stores the
 * pointer to the resulting (statically allocated) sockaddr and returns
 * 0, or else returns -1 on failure.
 */

int get_sockaddr(const char *address, const char *sport, struct sockaddr **addr)
{
    int n;
    long int port;

    errno = 0;
    port = strtol(sport, NULL, 10);
    if (errno != 0 || port == 0 || port >= 0xFFFF) {
        fprintf(stderr, "Couldn't parse '%s' as port number\n", sport);
        return -1;
    }

    n = inet_pton(AF_INET6, address, (void *) &in6_addr.sin6_addr);
    if (n == 1) {
        in6_addr.sin6_family = AF_INET6;
        in6_addr.sin6_port = htons((short) port);
        *addr = (struct sockaddr *) &in6_addr;
        return 0;
    }

    n = inet_pton(AF_INET, address, (void *) &in_addr.sin_addr);
    if (n == 1) {
        in_addr.sin_family = AF_INET;
        in_addr.sin_port = htons((short) port);
        *addr = (struct sockaddr *) &in_addr;
        return 0;
    }

    fprintf(stderr, "Couldn't parse '%s' as an IP address\n", address);

    return -1;
}


/*
 * Given a sockaddr and a role (1 for server, 0 for client), creates a
 * UDP socket and either binds or connects the given sockaddr to it.
 * Returns the socket on success, or -1 on failure.
 */

int udp_socket(const struct sockaddr *server, int role)
{
    int sock;
    socklen_t len;

    sock = socket(server->sa_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Couldn't create socket: %s\n", strerror(errno));
        return -1;
    }

    len = sizeof(struct sockaddr_in);
    if (server->sa_family == AF_INET6)
        len = sizeof(struct sockaddr_in6);

    if (role == 1 && bind(sock, server, len) < 0) {
        fprintf(stderr, "Can't bind socket: %s\n", strerror(errno));
        return -1;
    }

    else if (role == 0 && connect(sock, server, len) < 0) {
        fprintf(stderr, "Can't connect socket: %s\n", strerror(errno));
        return -1;
    }

    return sock;
}


/*
 * Sets the O_NONBLOCK flag on the given fd if blocking is non-zero, or
 * clears it if blocking is zero. Returns 0 on success and -1 on error.
 */

int set_blocking(int fd, int blocking)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (!blocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;

    return 0;
}


/*
 * Stays in a loop reading packets from both the TAP device and the UDP
 * socket. Encrypts and forwards packets from TAP→UDP, and decrypts and
 * forwards in the other direction.
 */

int tunnel(int role, const struct sockaddr *server, int tap,
           int udp, unsigned char oursk[KEYBYTES],
           unsigned char theirpk[KEYBYTES])
{
    int maxfd;
    unsigned char buf[65536];
    unsigned char k[crypto_box_BEFORENMBYTES];
    struct sockaddr_in pin_addr;
    struct sockaddr_in pin6_addr;
    struct sockaddr *client;
    socklen_t clientlen;

    /*
     * Precompute a shared secret from the two keys.
     */

    crypto_box_beforenm(k, oursk, theirpk);

    /*
     * The client always knows where to send UDP packets, but the server
     * has to wait until it receives a valid packet from the client. To
     * keep the code simple, both sides always use sendto(). The client
     * does connect on the socket, but the server doesn't (so that it
     * can accept packets from a client whose IP address has changed).
     * Here we set up a sockaddr_in{,6} for the client address.
     */

    if (server->sa_family == AF_INET6) {
        memset(&pin6_addr, 0, sizeof(pin6_addr));
        client = (struct sockaddr *) &pin6_addr;
        clientlen = sizeof(pin6_addr);
    }
    else {
        memset(&pin_addr, 0, sizeof(pin_addr));
        client = (struct sockaddr *) &pin_addr;
        clientlen = sizeof(pin_addr);
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
         * The server doesn't listen for TAP packets until it knows its
         * client's address. The client always listens.
         */

        if (role == 0 || client->sa_family != 0)
            FD_SET(tap, &r);

        err = select(maxfd+1, &r, NULL, NULL, NULL);
        if (err < 0)
            return n;

        /*
         * We read a complete packet from the UDP socket (or die if our
         * ridiculously large buffer is still not enough to prevent the
         * packet from being truncated) and try to decrypt it. If that
         * fails, we discard the packet silently. Otherwise we write
         * the decrypted result to the TAP fd in one go.
         */

        if (FD_ISSET(udp, &r)) {
            while (1) {
                n = recvfrom(udp, (void *) buf, 65536, MSG_DONTWAIT|MSG_TRUNC,
                             client, &clientlen);

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
                    char clientaddr[256] = "UNKNOWN";
                    const void *addr;
                    int port;

                    if (client->sa_family == AF_INET6) {
                        struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) &client;
                        addr = (const void *) &sin6->sin6_addr;
                        port = sin6->sin6_port;
                    }
                    else {
                        struct sockaddr_in * sin = (struct sockaddr_in *) &client;
                        addr = (const void *) &sin->sin_addr;
                        port = sin->sin_port;
                    }

                    (void) inet_ntop(client->sa_family, addr, clientaddr, 256);

                    if (n == 0) {
                        fprintf(stderr, "Orderly shutdown from client %s:%d; ignoring\n",
                                clientaddr, port);
                    }
                    else {
                        fprintf(stderr, "Received oversize (%d bytes) packet from "
                                "client %s:%d; ignoring\n", clientaddr, port);
                    }

                    continue;
                }

                /*
                 * We have a complete packet. Write it to the TAP device
                 * (without any decryption yet).
                 */

                set_blocking(tap, 1);
                if (write(tap, buf, n) < 0) {
                    fprintf(stderr, "Error writing to TAP: %s\n", strerror(errno));
                    return -1;
                }
                set_blocking(tap, 0);
            }
        }

        /*
         * We read ethernet frames from the TAP device in much the same
         * way as above, except that we use read and sendto instead of
         * recfrom and write.
         */

        if (FD_ISSET(tap, &r)) {
            while (1) {
                const struct sockaddr *target;
                socklen_t tlen;

                n = read(tap, buf, 65536);

                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                }

                if (n == 0) {
                    fprintf(stderr, "TAP fd closed; exiting\n");
                    return -1;
                }

                if (role == 0) {
                    target = server;
                    tlen = sizeof(struct sockaddr_in);
                    if (server->sa_family == AF_INET6)
                        tlen = sizeof(struct sockaddr_in6);
                }
                else {
                    if (client->sa_family == 0)
                        continue;
                    target = client;
                    tlen = clientlen;
                }

                err = sendto(udp, buf, n, 0, target, tlen);
                if (err < 0) {
                    fprintf(stderr, "Error writing to UDP: %s\n", strerror(errno));
                    return -1;
                }
            }
        }
    }
}
