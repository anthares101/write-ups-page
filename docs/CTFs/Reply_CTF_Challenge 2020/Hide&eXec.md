---
description: Hide & eXec [300] Reply CTF Challenge 2020 challenge write up.
---

# Hide & eXec [300]

The zip contains an image and a protected zip file. The image is some kind of bar code that after decoding will give you a code in some programing language: Java, Bash, Python, Javascript, PHP or Brainfuck (Yeah, im serious). This code will print the password for the protected zip after execution and after extract it we will get... another bar code and another protected zip file (Repeat this a lot of times)

This is the code we used to get the flag:


```
import glob
import re
import os
import sys
import contextlib
import execjs
import zxing

from io import StringIO
from subprocess import Popen, PIPE, run
from brainfuck import brainfuck


@contextlib.contextmanager
def stdoutIO(stdout=None):
    old = sys.stdout
    if stdout is None:
        stdout = StringIO()
    sys.stdout = stdout
    yield stdout
    sys.stdout = old

def php(code):
	# open process
	process = Popen(['php'], stdout=PIPE, stdin=PIPE, close_fds=True)

	# read output
	out = process.communicate(code.encode())[0]

	# kill process
	try:
		os.kill(process.pid, signal.SIGTERM)
	except:
		pass

	# return
	return out.decode()

def java(code):
	# open process
	process = Popen(['jshell'], stdout=PIPE, stdin=PIPE, close_fds=True)

	# read output
	out = process.communicate(f'{code}\n {"Main.main(new String[0])"}\n'.encode())[0]

	# kill process
	try:
		os.kill(process.pid, signal.SIGTERM)
	except:
		pass

	strings_list = out.decode().split()
	return strings_list[len(strings_list)-2]

def bash(code):
	# open process
	process = Popen(['bash'], stdout=PIPE, stdin=PIPE, close_fds=True)

	# read output
	out = process.communicate(code.encode())[0]

	# kill process
	try:
		os.kill(process.pid, signal.SIGTERM)
	except:
		pass

	return out.decode().strip()


checked_files = []

# Init reader
reader = zxing.BarCodeReader()

# Get first file basename
basename = glob.glob('*.zip')[0].split(".")[0]

while basename:
	# Try to decode image
	dataObject = reader.decode(f'{basename}.png')
	code = dataObject.raw

	# Execute the code and get the pass
	print("=========EXTRACTED CODE=========")
	password = ""
	if("<?php" in code): # PHP
		print(code)

		password = php(code)
	elif("class" in code): # Java
		print(code)

		password = java(code)
	elif("$" in code): # Bash
		print(code)

		password = bash(code)
	elif(";" in code): # JS
		# Try to fix JS code
		jsCode = code.replace("console.log(output);", "return output")
		print(jsCode)

		password = execjs.exec_(jsCode)
	elif("+++" in code): # Brainfuck (Are you serious????)
		print(code)

		with stdoutIO() as s:
			brainfuck.evaluate(code)
			password = s.getvalue().strip()
	else: # Python
		# Try to fix python code
		print(code)

		with stdoutIO() as s:
			exec(code)
			password = s.getvalue().strip()
	print("================================")

	# Print zip password and extract files
	print(f'Password for {basename}: {password}')
	with open(os.devnull, 'w') as null:
		run(['7z', 'x', f'{basename}.zip', f'-p{password}'], stdout=null, stderr=null)

	# Add extracted file to checked files
	checked_files.append(f'{basename}.zip')

	# Select next file
	basename = None
	zip_files = glob.glob('*.zip')
	for zip_file in zip_files:
		if zip_file not in checked_files:
			basename = zip_file.split(".")[0]
			break
```

The last zip file password is the flag: `{FLG:P33k-4-b0o!UF0undM3,Y0urT0olb0xIsGr8!!1}`
