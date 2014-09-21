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

#define KEYBYTES 32

int tap_attach(const char *name);
int read_key(const char *name, unsigned char key[KEYBYTES]);
int get_sockaddr(const char *address, const char *sport,
                 struct sockaddr **addr, socklen_t *len);
int udp_socket(int role, const struct sockaddr *server,
               socklen_t srvlen);
int set_blocking(int fd, int blocking);

#endif
