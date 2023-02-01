---
description: Delivery box from HackTheBox write up.
---

# Delivery

## Nmap

Looks like there are two web servers running in the machine, I will start checking port 80 first and then we can go with the 8065. I know SSH is there but since I have no credentials and the version is not too old let's move on for now.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate=1000 10.10.10.222
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 18:04 CET
Nmap scan report for 10.10.10.222
Host is up (0.048s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8065/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.39 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22,80,8065 -sC -sV 10.10.10.222
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 18:06 CET
Nmap scan report for helpdesk.delivery.htb (10.10.10.222)
Host is up (0.041s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c40fa859b01acac0ebc0c19518aee27 (RSA)
|   256 5a0cc03b9b76552e6ec4f4b95d761709 (ECDSA)
|_  256 b79df7489da2f27630fd42d3353a808c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-title: delivery
|_http-server-header: nginx/1.14.2
8065/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Wed, 01 Feb 2023 16:59:37 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: sz4pfpnxf38t7j84ks8rsrhn8w
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Wed, 01 Feb 2023 17:06:38 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Wed, 01 Feb 2023 17:06:38 GMT
|_    Content-Length: 0

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.44 seconds
```

## Port 80

We have a pretty simple website http://delivery.htb/ (Remember to add the domain to your host file!) where the only interesting thing was a link to http://helpdesk.delivery.htb/. The virtual host is serving a Osticket application for ticketing, looks updated and the staff login in http://helpdesk.delivery.htb/scp/login.php is not accepting the default credentials so I guess that is time to keep going.

## Port 8065

A Mattermost installation, again looks updated. I can register but I need to confirm my email, that is a problem because I'm not really able to get the email... or maybe I can. Well, the help desk application, when creating a ticket, provides a custom `@delivery.htb` email that we can use to send updates to the ticket thread.

Since we have access to that thread, we could use that ticket email for Mattermost registration and get our confirmation email in the ticket thread! As you can see, we can now confirm our account:

```
---- Registration Successful ---- Please activate your email by going to: http://delivery.htb:8065/do_verify_email?token=zzsen61145xqsq68ya3k6wtipt9wnb5e9yxupcd9pkfmyoisaw3ngc7qwxw6tm6z&email=9517485%40delivery.htb ) --------------------- You can sign in from: --------------------- Mattermost lets you share messages and files from your PC or phone, with instant search and archiving. For the best experience, download the apps for PC, Mac, iOS and Android from: https://mattermost.com/download/#mattermostApps ( https://mattermost.com/download/#mattermostApps
```

Cool, inside Mattermost I can join a team called `Internal`. There, I got credentials for SSH `maildeliverer:Youve_G0t_Mail!`.

# In the box

## Getting some hashes

After an initial enumeration trying to find low hanging fruits, I decided to look into the MySQL database that is running in the system. For that, we can just go to the Mattermost configuration directory and get the credentials for it. Fun fact, the password to access the database is actually a hint for the next step.

```bash
maildeliverer@Delivery:/var/www/osticket$ netstat -ltpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1025          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
tcp6       0      0 :::8065                 :::*                    LISTEN      - 


maildeliverer@Delivery:/opt/mattermost/config$ cat config.json | grep mysql -A 10
        "DriverName": "mysql",
     -->"DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
        "DataSourceReplicas": [],
        "DataSourceSearchReplicas": [],
        "MaxIdleConns": 20,
        "ConnMaxLifetimeMilliseconds": 3600000,
        "MaxOpenConns": 300,
        "Trace": false,
        "AtRestEncryptKey": "n5uax3d4f919obtsp1pw1k5xetq1enez",
        "QueryTimeout": 30,
        "DisableDatabaseSearch": false
```

Inside MySQL, I searched for the Mattermost user table and looks like there is a user called `root` registered. If that is the same `root` as in the system and we can crack the password we win!

```sql
MariaDB [mattermost]> select Username,Password from Users;
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
|...																							  |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
|...																							  |
+----------------------------------+--------------------------------------------------------------+
```

## Pwned!

The Rockyou dictionary failed to crack the password but in the Mattermost chat, there is a comment about not using passwords like: `PleaseSubscribe!` or variants of it. Maybe, using some rules and that password could be enough to crack it.

After some try and error, I was able to crack the hash using Hashcat and the rule called `rockyou-30000.rule`. The password is `PleaseSubscribe!21` and we can use it to escalate to `root`!
