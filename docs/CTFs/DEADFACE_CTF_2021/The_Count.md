---
title: The Count
description: The Count DEADFACE CTF 2021 challenge write up.
---

# The Count <a href='/assets/resources/CTFs/DEADFACE_CTF_2021/TheCount-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## Enumeration

Trying to connect to the service provided by the challenge will ask for the sum of a word:
```bash
┌──(kali㉿kali)-[~]
└─$ nc code.deadface.io 50000
DEADFACE gatekeeper: Let us see how good your programming skills are.
If a = 0, b = 1, c = 2, etc.. Tell me what the sum of this word is:

 You have 5 seconds to give me an answer.

Your word is: classy
Too slow!! Word has been reset!
```

With only 5 seconds it is pretty hard to do by hand so Python time!

## Python knows best

I went for `pwntools` because it is an easy to use Python framework for this kind of things. We have to connect to the service, get the word and then calculate the sum of its letters. Using `string.ascii_lowercase` we can get a lower case alphabet string that we can use with the `find` function to get the values of every letter.

Translating all of the above to Python code, this is the result:
```python
#! /usr/bin/env python3

from pwn import *
import string


alphabet = string.ascii_lowercase

challenge = remote('code.deadface.io', 50000)
challenge.recvuntil('Your word is: ')
word = challenge.recv().decode().strip()

print(f'The word is --> {word}')
word_sum = 0
for letter in word:
	word_sum += alphabet.find(letter)
print(f'Its value is --> {word_sum}')

challenge.send(str(word_sum))
flag = challenge.recv().decode().strip()
print(f'Flag --> {flag}')

challenge.close()
``` 

Executing the code will give the flag:
```bash
┌──(kali㉿kali)-[~/Desktop/TODO/The Count]
└─$ ./get_flag.py     
[+] Opening connection to code.deadface.io on port 50000: Done
The word is --> humor
Its value is --> 70
Flag --> flag{d1c037808d23acd0dc0e3b897f344571ddce4b294e742b434888b3d9f69d9944}
[*] Closed connection to code.deadface.io port 50000
```
