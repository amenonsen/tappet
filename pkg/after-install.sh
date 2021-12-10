#!/bin/bash

id tappet &>/dev/null || useradd -d /var/lib/tappet -m -s /bin/false -r tappet
test -f /var/lib/tappet/$(hostname -s).key || su -s /bin/bash - tappet -c '/usr/sbin/tappet-keygen $(hostname -s)'
