#ifndef TAPPET_H
#define TAPPET_H

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

#define KEYBYTES 32
#define ZEROBYTES crypto_box_ZEROBYTES
#define NONCEBYTES crypto_box_NONCEBYTES

int tap_attach(const char *name);
int read_key(const char *name, unsigned char key[KEYBYTES]);
int get_sockaddr(const char *address, const char *sport,
                 struct sockaddr **addr, socklen_t *addrlen);
int udp_socket(int role, const struct sockaddr *server,
               socklen_t srvlen);
void describe_sockaddr(const struct sockaddr *addr, char *desc, int desclen);
int tap_read(int tap, unsigned char *buf, int len);
int tap_write(int tap, unsigned char *buf, int len);
int udp_read(int udp, unsigned char nonce[NONCEBYTES],
             unsigned char *buf, int len, struct sockaddr *addr,
             socklen_t *addrlen);
int udp_write(int udp, unsigned char nonce[NONCEBYTES],
              unsigned char *buf, int len, const struct sockaddr *addr,
              socklen_t addrlen);

void generate_nonce(int role, unsigned char nonce[NONCEBYTES]);
void update_nonce(int role, unsigned char nonce[NONCEBYTES]);
int decrypt(unsigned char k[crypto_box_BEFORENMBYTES],
            unsigned char nonce[NONCEBYTES],
            unsigned char *ctbuf, int ctlen,
            unsigned char *ptbuf);
int encrypt(unsigned char k[crypto_box_BEFORENMBYTES],
            unsigned char nonce[NONCEBYTES],
            unsigned char *ptbuf, int ptlen,
            unsigned char *ctbuf);

#endif
