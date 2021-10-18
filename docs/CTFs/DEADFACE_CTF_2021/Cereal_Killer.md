---
title: Cereal Killer
description: Cereal Killer DEADFACE CTF 2021 challenge write up.
---

# Cereal Killer <a href='/assets/resources/CTFs/DEADFACE_CTF_2021/CerealKiller-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

Using `strings` with the binary I noticed a weird string near the part where the program asks for a password: `c0unt-ch0cula`. Using it as the password that program is asking for will do!
```bash
┌──(kali㉿kali)-[~/Desktop/CTF/Deadface2021/Cereal Killer]
└─$ ./deadface_re01.bin                  
What is the best and sp00kiest breakfast cereal?
Please enter the passphrase: c0unt-ch0cula
flag{c0unt-ch0cula-cereal-FTW}
```
