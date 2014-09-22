#include "tappet.h"

static struct sockaddr_storage sock_addr;

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
    char line[64+1+1];
    char *p, *q;

    if (fgets(line, 64+1+1, f) == NULL || strlen(line) != 64+1 || line[64] != '\n')
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

int get_sockaddr(const char *address, const char *sport,
                 struct sockaddr **addr, socklen_t *addrlen)
{
    int n;
    long int port;
    struct sockaddr_in *in_addr = (struct sockaddr_in *) &sock_addr;
    struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *) &sock_addr;

    errno = 0;
    port = strtol(sport, NULL, 10);
    if (errno != 0 || port == 0 || port >= 0xFFFF) {
        fprintf(stderr, "Couldn't parse '%s' as port number\n", sport);
        return -1;
    }

    n = inet_pton(AF_INET6, address, (void *) &in6_addr->sin6_addr);
    if (n == 1) {
        in6_addr->sin6_family = AF_INET6;
        in6_addr->sin6_port = htons((short) port);
        *addr = (struct sockaddr *) in6_addr;
        *addrlen = sizeof(*in6_addr);
        return 0;
    }

    n = inet_pton(AF_INET, address, (void *) &in_addr->sin_addr);
    if (n == 1) {
        in_addr->sin_family = AF_INET;
        in_addr->sin_port = htons((short) port);
        *addr = (struct sockaddr *) in_addr;
        *addrlen = sizeof(*in_addr);
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

int udp_socket(int role, const struct sockaddr *server, socklen_t srvlen)
{
    int sock;

    sock = socket(server->sa_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Couldn't create socket: %s\n", strerror(errno));
        return -1;
    }

    if (role == 1 && bind(sock, server, srvlen) < 0) {
        fprintf(stderr, "Can't bind socket: %s\n", strerror(errno));
        return -1;
    }

    else if (role == 0 && connect(sock, server, srvlen) < 0) {
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
 * Given a pointer to a sockaddr, writes a description of it to the
 * given character array, or "[unknown]" if it cannot be described.
 */

void describe_sockaddr(const struct sockaddr *addr, char *desc, int desclen)
{
    const void *inaddr;
    char port[16];

    if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &addr;
        inaddr = (const void *) &sin6->sin6_addr;
        snprintf(port, 16, "[:%d]", sin6->sin6_port);
    }
    else {
        struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
        inaddr = (const void *) &sin->sin_addr;
        snprintf(port, 16, ":%d", sin->sin_port);
    }

    if (inet_ntop(addr->sa_family, inaddr, desc, desclen)) {
        strcat(desc, port);
    }
    else {
        strcpy(desc, "[unknown]");
    }
}


/*
 * Reads up to n characters into the buffer from the TAP device without
 * blocking. Returns the number of characters read on success, or 0 if
 * there were none available, or prints an error and returns -1 on
 * failure.
 */

int tap_read(int tap, unsigned char *buf, int len)
{
    int n;

    set_blocking(tap, 0);

    n = read(tap, buf, len);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        fprintf(stderr, "Error reading from TAP device: %s\n",
                strerror(errno));
        return n;
    }

    if (n == 0) {
        fprintf(stderr, "TAP device unexpectedly closed\n");
        return -1;
    }

    return n;
}


/*
 * Writes n characters from the given buffer to the TAP fd, which is set
 * to block before the write. Returns 0 on success, or prints an error
 * and returns -1 on failure.
 */

int tap_write(int tap, unsigned char *buf, int len)
{
    int n;

    set_blocking(tap, 1);

    n = write(tap, buf, len);

    if (n < 0) {
        fprintf(stderr, "Error writing to TAP: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}


/*
 * Reads up to n characters into the buffer from the UDP socket. Returns
 * the number of characters read on success, or 0 if there were no data
 * available, or -1 if the caller should try again (i.e., an error that
 * can be ignored), or prints an error and returns -2 on failure.
 */

int udp_read(int udp, unsigned char *buf, int len,
             struct sockaddr *addr, socklen_t *addrlen)
{
    int n;
    char peeraddr[256];

    n = recvfrom(udp, (void *) buf, len, MSG_DONTWAIT|MSG_TRUNC,
                 addr, addrlen);

    if (n > 0 && n <= len)
        return n;

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        fprintf(stderr, "Error reading from UDP socket: %s\n",
                strerror(errno));
        return -2;
    }

    /*
     * We complain at length about the "connection" closing
     * or receiving oversized packets, but we ultimately
     * ignore them and carry on.
     */

    describe_sockaddr(addr, peeraddr, 256);

    if (n == 0) {
        fprintf(stderr, "Orderly shutdown from %s; ignoring\n",
                peeraddr);
    }
    else if (n > len) {
        fprintf(stderr, "Received oversize (%d bytes) packet from "
                "%s; ignoring\n", n, peeraddr);
    }

    return -1;
}


/*
 * Sends n characters from the given buffer to the given address through
 * the UDP socket. Returns 0 on success, or prints an error and returns
 * -1 on failure.
 */

int udp_write(int udp, unsigned char *buf, int len,
              const struct sockaddr *addr, socklen_t addrlen)
{
    int n;

    n = sendto(udp, buf, len, 0, addr, addrlen);

    if (n < 0) {
        if (errno == EMSGSIZE) {
            /*
             * If this happens, it means the MTU on the TAP interfaces
             * is larger than the PMTU between the two ends of this
             * tunnel. We don't try to adjust the outer MTU (yet).
             */
            fprintf(stderr, "PMTU is <%d bytes, reduce TAP MTU; "
                    "dropping packet\n", len);
            return 0;
        }
        fprintf(stderr, "Error writing to UDP socket: %s\n",
                strerror(errno));
        return -1;
    }

    return 0;
}
