---
description: PasswordCheck HacktoberCTF 2020 challenge write up.
---

# PasswordCheck

Using the have i been pwned? API we wrote a program that will check every password hash provided and check how many times a certain password was compromised. After processing all the hashes, the program will check the most compromised hash and return the that hash and the number of times compromised.

The program is this:

```
import requests


# Read passwords hashes file
file = open("FL1R0jbn", "r")
lines = file.readlines()
file.close()

hashes = []
# Strips the newline character 
for line in lines: 
	hashes.append(line.strip().upper())

host = "https://api.pwnedpasswords.com/range/"
pwnedTimes = []
for hash in hashes:
	response = requests.get(f'{host}{hash[:5]}')
	foundHashesSuffixes = response.content.splitlines()
	found = False
	for foundHashSuffix in foundHashesSuffixes:
		if(hash[5:] in foundHashSuffix.decode()):
			print(f"Hash found! --> {hash}")
			num = foundHashSuffix.decode().split(':')[1]
			pwnedTimes.append(int(num))
			found = True
			break;
	if not found:
		pwnedTimes.append(0)

maxValue = max(pwnedTimes)
maxValueIndex = pwnedTimes.index(maxValue)
print(f'The most compromised password was compromised {maxValue} times')
print(f'The password hash is {hashes[maxValueIndex]}')
```

The output was:

```
Hash found! --> C2577430D91716490DC5D33C20D901E008B696E7
The most compromised password was compromised 55001 times
The password hash is C2577430D91716490DC5D33C20D901E008B696E7
```

Using crackstation we got the plain text password: ncc1701
Therefore, the flag is:

`flag{55001_ncc1701}`