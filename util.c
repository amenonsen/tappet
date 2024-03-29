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
        a = a - 'a' + 10;
    else
        return -1;

    b = *(s+1) | 0x20;
    if (b >= '0' && b <= '9')
        b -= '0';
    else if (b >= 'a' && b <= 'f')
        b = b - 'a' + 10;
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
 * Opens the given file, makes sure it contains exactly four bytes,
 * reads the bytes and interprets them as an unsigned 32-bit integer,
 * increments the integer, checks that it did not overflow, writes the
 * four modified bytes back out to the start of the file, and closes it.
 * Returns a non-zero 32-bit nonce on success, or 0 on failure of any of
 * the steps above.
 */

uint32_t get_nonce_prefix(const char *name)
{
    int fd, n;
    struct stat st;
    unsigned char buf[4];

    fd = open(name, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Couldn't open nonce file %s: %s\n", name,
                strerror(errno));
        return 0;
    }

    n = fstat(fd, &st);
    if (n < 0) {
        fprintf(stderr, "Couldn't fstat nonce file %s: %s\n", name,
                strerror(errno));
        return 0;
    }
    if (st.st_size != 4) {
        fprintf(stderr, "Nonce file %s must contain exactly 4 bytes, not %lu\n",
                name, st.st_size);
        return 0;
    }

    n = read(fd, buf, 4);
    if (n != 4) {
        if (n < 0)
            fprintf(stderr, "Couldn't read from nonce file %s: %s\n", name,
                    strerror(errno));
        else
            fprintf(stderr, "Expected 4 bytes from nonce file %s, got %d bytes\n",
                    name, n);
        return 0;
    }

    *(uint32_t *)buf += 1;
    if (*(uint32_t *)buf == 0) {
        fprintf(stderr, "Nonce prefix overflow; cannot continue\n"
                "Regenerate keys on both peers and reset nonce files.\n");
        return 0;
    }

    if (lseek(fd, 0, SEEK_SET) != 0 ||
        write(fd, buf, 4) != 4 ||
        close(fd) != 0)
    {
        fprintf(stderr, "Couldn't rewrite nonce file %s: %s\n", name,
                strerror(errno));
        return 0;
    }

    return *(uint32_t *)buf;
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
 * Creates a UDP socket, and if listen is 1, also binds it to the given
 * server address. Returns the socket on success, or -1 on failure.
 */

int udp_socket(int listen, const struct sockaddr *server, socklen_t srvlen)
{
    int sock;
    int val;

    sock = socket(server->sa_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Couldn't create socket: %s\n", strerror(errno));
        return -1;
    }

    if (listen == 1 && bind(sock, server, srvlen) < 0) {
        fprintf(stderr, "Can't bind socket: %s\n", strerror(errno));
        return -1;
    }

    val = IP_PMTUDISC_DO;
    (void) setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));

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

    if (set_blocking(tap, 0) < 0) {
        fprintf(stderr, "Couldn't set TAP device to non-blocking: %s\n",
                strerror(errno));
        return -1;
    }

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

    if (set_blocking(tap, 1) < 0) {
        fprintf(stderr, "Couldn't set TAP device to blocking: %s\n",
                strerror(errno));
        return -1;
    }

    n = write(tap, buf, len);

    if (n < 0) {
        fprintf(stderr, "Error writing to TAP: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}


/*
 * Reads the complete nonce and up to len bytes of data from the UDP
 * socket into the given buffer.
 *
 * Returns the number of bytes stored in the buffer on success (i.e.,
 * when a complete nonce and a complete packet were read).
 *
 * Otherwise returns 0 if there were no bytes to be read. Returns -1 if
 * the caller should try again (i.e., an error occurred that can be
 * ignored), or prints an error and returns -2 on failure.
 */

int udp_read(int udp,unsigned char nonce[NONCEBYTES],
             unsigned char *buf, int len, struct sockaddr *addr,
             socklen_t *addrlen)
{
    int n;
    struct msghdr msg;
    struct iovec iov[2];
    char peeraddr[256];

    iov[0].iov_base = nonce;
    iov[0].iov_len = NONCEBYTES;

    iov[1].iov_base = buf;
    iov[1].iov_len = len;

    msg.msg_name = (void *) addr;
    msg.msg_namelen = *addrlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    n = recvmsg(udp, &msg, MSG_DONTWAIT|MSG_TRUNC);

    *addrlen = msg.msg_namelen;

    if (n > NONCEBYTES && !(msg.msg_flags & MSG_TRUNC))
        return n-NONCEBYTES;

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        fprintf(stderr, "Error reading from UDP socket: %s\n",
                strerror(errno));
        return -2;
    }

    /*
     * We complain about some errors to aid debugging, but ultimately
     * ignore them and move on.
     */

    describe_sockaddr(addr, peeraddr, 256);

    if (n == 0) {
        fprintf(stderr, "Orderly shutdown from %s; ignoring\n",
                peeraddr);
    }
    else if (n <= NONCEBYTES) {
        fprintf(stderr, "Received undersize (%d bytes) packet from "
                "%s; ignoring\n", n, peeraddr);
    }
    else if (msg.msg_flags & MSG_TRUNC) {
        fprintf(stderr, "Received oversize (%d bytes) packet from "
                "%s; ignoring\n", n, peeraddr);
    }

    return -1;
}


/*
 * Sends a nonce and len bytes from the given buffer through the UDP
 * socket. Returns 0 on success, or prints an error and returns -1 on
 * failure.
 */

int udp_write(int udp, unsigned char nonce[NONCEBYTES],
              unsigned char *buf, int len, const struct sockaddr *addr,
              socklen_t addrlen)
{
    int n;
    struct msghdr msg;
    struct iovec iov[2];

    iov[0].iov_base = nonce;
    iov[0].iov_len = NONCEBYTES;

    iov[1].iov_base = buf;
    iov[1].iov_len = len;

    msg.msg_name = (void *) addr;
    msg.msg_namelen = addrlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    n = sendmsg(udp, &msg, 0);

    if (n < 0) {
        if (errno == EMSGSIZE) {
            /*
             * This means that (PMTU discovery is miraculously working
             * and) the PMTU between the two ends of this tunnel is not
             * large enough to accommodate the packets we're sending. We
             * do not reduce the MTU on the TAP interfaces to compensate
             * for this (yet).
             */
            fprintf(stderr, "PMTU is <%d bytes, set TAP MTU to <%d; "
                    "dropping packet\n", len, len-74);
            return 0;
        }
        else if (errno == ENETUNREACH) {
            /*
             * This means that tappet was started before we established
             * a connection to the network, so we have no choice but to
             * discard whatever this packet is.
             */
            return 0;
        }
        fprintf(stderr, "Error writing to UDP socket: %s\n",
                strerror(errno));
        return -1;
    }

    return 0;
}
