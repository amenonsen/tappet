/*
 * Abhijit Menon-Sen <ams@toroid.org>
 * Public domain; 2014-09-20
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "tweetnacl.h"

int main(int argc, char *argv[])
{
    int n, fd;
    struct ifreq ifr;

    /*
     * We attach to the TAP interface whose name is given as our first
     * argument (as described in Documentation/networking/tuntap.txt).
     * If this code is run as root, it will create the interface. (It
     * would be nice to report a more useful error when the interface
     * doesn't exist, but TUNGETIFF works on the attached fd; we have
     * only an interface name.)
     */

    if (argc < 2) {
        fprintf(stderr, "Usage: tappet <if-name>\n");
        return -1;
    }

    if (geteuid() == 0) {
        fprintf(stderr, "Please run tappet as an ordinary user\n");
        return -1;
    }

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Couldn't open /dev/net/tun: %s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
    ifr.ifr_flags = IFF_TAP;

    n = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (n < 0) {
        fprintf(stderr, "Couldn't attach to %s: %s\n", argv[1], strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * Now decide what to do: accept connections or connect to a server.
     */

    return 0;
}
