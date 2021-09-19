---
title: N1P
description: N1P H@cktivityCon 2021 challenge write up.
---

# N1P <a href='/assets/resources/CTFs/H@cktivityCon_2021/N1P-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

After tryng the program a bit I noticed that using `flag{` as input the first part of the new encrypted text and the encrypted flag was the same. I coded a program that will try every possible combination of characters position by position calculating which of the character produce the best output:


```python
#!/usr/bin/env python3

from pwn import *

connection = remote('challenge.ctf.games',31921)

def get_guess_fitness(encrypted_flag: str, guessed_flag: str):
	mathing_characters = 0
	for encrypted_flag_character, guessed_flag_character in zip(encrypted_flag, guessed_flag):
		if(encrypted_flag_character == guessed_flag_character):
			mathing_characters +=  1
		else:
			break

	return mathing_characters / len(encrypted_flag)
	

with log.progress('Getting encrypted flag...') as p:
	connection.recvline('NINA: Hello! I found a flag, look!')
	encrypted_flag = connection.recvline().decode().strip()

with log.progress('Guessing flag...') as p:
	flag_guess = ''
	current_fitness = 0;
	alphabet = list(string.printable)[:-6]

	while current_fitness != 1:
		new_character = ''

		for character in alphabet:
			p.status(flag_guess + character)
			connection.recv()
			connection.send(flag_guess + character)
			connection.recvline("""connection.recvline('NINA: Ta-daaa!! I think this is called a 'one' 'time' 'pad' or something?')""")

			encrypted_guess = connection.recvline().decode().strip()
			new_fitness = get_guess_fitness(encrypted_flag, encrypted_guess)
			if(new_fitness > current_fitness):
				new_character = character
				current_fitness = new_fitness

		flag_guess += new_character

	p.success(flag_guess)

connection.close()
```

Executing the program will give us the flag:

```bash
┌──(kali㉿kali)-[~/Desktop/CTF/Hacktivity/N1P]
└─$ ./flag_guesser.py
[+] Opening connection to challenge.ctf.games on port 31921: Done
[+] Getting encrypted flag...: Done
[+] Guessing flag...: flag{9276cdb76a3dd6b1f523209cd9c0a11b}
[*] Closed connection to challenge.ctf.games port 31921
```
