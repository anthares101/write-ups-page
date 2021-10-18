---
title: Old Devil
description: Old Devil DEADFACE CTF 2021 challenge write up.
---

# Old Devil <a href='/assets/resources/CTFs/DEADFACE_CTF_2021/OldDevil-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## Analysis

After a while looking aroung in Ghidra, I found that the 'Demon name' that the programs asks for is generated before asking for it. Using Radare (Yeah Im one of those) I can set a breakpoint in the program and check the stack to read it:

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ r2 -d ./demon
Process with PID 14834 started...
= attach 14834 14834
bin.baddr 0x56412de10000
Using 0x56412de10000
asm.bits 64
[0x7fdf8f579050]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x7fdf8f579050]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x7fdf8f579050]> pdf@main
            ; DATA XREF from entry0 @ 0x56412de1109d
┌ 304: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_50h @ rbp-0x50
│           ; var int64_t var_3fh @ rbp-0x3f
│           ; var int64_t var_3bh @ rbp-0x3b
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_2fh @ rbp-0x2f
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_1h @ rbp-0x1
│           0x56412de11165      55             push rbp
│           0x56412de11166      4889e5         mov rbp, rsp
│           0x56412de11169      4883ec50       sub rsp, 0x50
│           0x56412de1116d      c645ff4e       mov byte [var_1h], 0x4e ; 'N' ; 78
│           0x56412de11171      488d05900e00.  lea rax, [0x56412de12008]
│           0x56412de11178      488945e8       mov qword [var_18h], rax
│           0x56412de1117c      488d05920e00.  lea rax, str.kaljvLi    ; 0x56412de12015 ; "kaljvLi\x7fl@@ha>nep"
│           0x56412de11183      488945e0       mov qword [var_20h], rax
│           0x56412de11187      c745f8000000.  mov dword [var_8h], 0
│       ┌─< 0x56412de1118e      eb36           jmp 0x56412de111c6
│      ┌──> 0x56412de11190      8b45f8         mov eax, dword [var_8h]
│      ╎│   0x56412de11193      4863d0         movsxd rdx, eax
│      ╎│   0x56412de11196      488b45e0       mov rax, qword [var_20h]
│      ╎│   0x56412de1119a      4801d0         add rax, rdx
│      ╎│   0x56412de1119d      0fb600         movzx eax, byte [rax]
│      ╎│   0x56412de111a0      84c0           test al, al
│     ┌───< 0x56412de111a2      741e           je 0x56412de111c2
│     │╎│   0x56412de111a4      8b45f8         mov eax, dword [var_8h]
│     │╎│   0x56412de111a7      4863d0         movsxd rdx, eax
│     │╎│   0x56412de111aa      488b45e0       mov rax, qword [var_20h]
│     │╎│   0x56412de111ae      4801d0         add rax, rdx
│     │╎│   0x56412de111b1      0fb600         movzx eax, byte [rax]
│     │╎│   0x56412de111b4      83f00d         xor eax, 0xd            ; 13
│     │╎│   0x56412de111b7      89c2           mov edx, eax
│     │╎│   0x56412de111b9      8b45f8         mov eax, dword [var_8h]
│     │╎│   0x56412de111bc      4898           cdqe
│     │╎│   0x56412de111be      885405b0       mov byte [rbp + rax - 0x50], dl
│     └───> 0x56412de111c2      8345f801       add dword [var_8h], 1
│      ╎│   ; CODE XREF from main @ 0x56412de1118e
│      ╎└─> 0x56412de111c6      837df811       cmp dword [var_8h], 0x11
│      └──< 0x56412de111ca      7ec4           jle 0x56412de11190
│           0x56412de111cc      c645c100       mov byte [var_3fh], 0
│           0x56412de111d0      c745f4000000.  mov dword [var_ch], 0
│       ┌─< 0x56412de111d7      eb36           jmp 0x56412de1120f
│      ┌──> 0x56412de111d9      8b45f4         mov eax, dword [var_ch]
│      ╎│   0x56412de111dc      4863d0         movsxd rdx, eax
│      ╎│   0x56412de111df      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x56412de111e3      4801d0         add rax, rdx
│      ╎│   0x56412de111e6      0fb600         movzx eax, byte [rax]
│      ╎│   0x56412de111e9      84c0           test al, al
│     ┌───< 0x56412de111eb      741e           je 0x56412de1120b
│     │╎│   0x56412de111ed      8b45f4         mov eax, dword [var_ch]
│     │╎│   0x56412de111f0      4863d0         movsxd rdx, eax
│     │╎│   0x56412de111f3      488b45e8       mov rax, qword [var_18h]
│     │╎│   0x56412de111f7      4801d0         add rax, rdx
│     │╎│   0x56412de111fa      0fb600         movzx eax, byte [rax]
│     │╎│   0x56412de111fd      83f00d         xor eax, 0xd            ; 13
│     │╎│   0x56412de11200      89c2           mov edx, eax
│     │╎│   0x56412de11202      8b45f4         mov eax, dword [var_ch]
│     │╎│   0x56412de11205      4898           cdqe
│     │╎│   0x56412de11207      885405c5       mov byte [rbp + rax - 0x3b], dl
│     └───> 0x56412de1120b      8345f401       add dword [var_ch], 1
│      ╎│   ; CODE XREF from main @ 0x56412de111d7
│      ╎└─> 0x56412de1120f      837df40a       cmp dword [var_ch], 0xa
│      └──< 0x56412de11213      7ec4           jle 0x56412de111d9
│           0x56412de11215      c645d000       mov byte [var_30h], 0
│           0x56412de11219      488d3d080e00.  lea rdi, str._nLuciafer_v1.0_nSay_the_demons_name_to_gain_access_to_the_secret. ; 0x56412de12028 ; "\nLuciafer v1.0\nSay the demon's name to gain access to the secret."                                                                                                                                           
│           0x56412de11220      e80bfeffff     call sym.imp.puts       ; int puts(const char *s)
│           0x56412de11225      488d3d3e0e00.  lea rdi, str.Enter_the_demons_name:_ ; 0x56412de1206a ; "Enter the demon's name: "
│           0x56412de1122c      b800000000     mov eax, 0
│           0x56412de11231      e80afeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x56412de11236      488d45d1       lea rax, [var_2fh]
│           0x56412de1123a      4889c7         mov rdi, rax
│           0x56412de1123d      b800000000     mov eax, 0
│           0x56412de11242      e819feffff     call sym.imp.gets       ; char *gets(char *s)
│           0x56412de11247      488d55c5       lea rdx, [var_3bh]
│           0x56412de1124b      488d45d1       lea rax, [var_2fh]
│           0x56412de1124f      4889d6         mov rsi, rdx
│           0x56412de11252      4889c7         mov rdi, rax
│           0x56412de11255      e8f6fdffff     call sym.imp.strcmp     ; int strcmp(const char *s1, const char *s2)
│           0x56412de1125a      85c0           test eax, eax
│       ┌─< 0x56412de1125c      740e           je 0x56412de1126c
│       │   0x56412de1125e      488d3d230e00.  lea rdi, str._nThat_is_not_the_demons_name. ; 0x56412de12088 ; "\nThat is not the demon's name."
│       │   0x56412de11265      e8c6fdffff     call sym.imp.puts       ; int puts(const char *s)
│      ┌──< 0x56412de1126a      eb10           jmp 0x56412de1127c
│      │└─> 0x56412de1126c      488d3d340e00.  lea rdi, str._nYou_are_correct. ; 0x56412de120a7 ; "\nYou are correct."
│      │    0x56412de11273      e8b8fdffff     call sym.imp.puts       ; int puts(const char *s)
│      │    0x56412de11278      c645ff59       mov byte [var_1h], 0x59 ; 'Y' ; 89
│      │    ; CODE XREF from main @ 0x56412de1126a
│      └──> 0x56412de1127c      807dff4e       cmp byte [var_1h], 0x4e
│       ┌─< 0x56412de11280      740c           je 0x56412de1128e
│       │   0x56412de11282      488d45b0       lea rax, [var_50h]
│       │   0x56412de11286      4889c7         mov rdi, rax
│       │   0x56412de11289      e8a2fdffff     call sym.imp.puts       ; int puts(const char *s)
│       └─> 0x56412de1128e      b800000000     mov eax, 0
│           0x56412de11293      c9             leave
└           0x56412de11294      c3             ret
[0x7fdf8f579050]> db 0x56412de11219
[0x7fdf8f579050]> dc
[+] SIGNAL 28 errno=0 addr=0x00000000 code=128 si_pid=0 ret=0
[0x7fdf8f579050]> dc
hit breakpoint at: 0x56412de11219
[0x56412de11219]> px @ rbp-0x3b
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffd70c20e65  4164 7261 6d6d 656c 6563 6800 0000 0000  Adrammelech.....                                                                                                                                     
0x7ffd70c20e75  0000 0000 0000 0000 0000 0015 20e1 2d41  ............ .-A
0x7ffd70c20e85  5600 0008 20e1 2d41 5600 0090 0fc2 700b  V... .-AV.....p.
0x7ffd70c20e95  0000 0012 0000 0000 0000 4ea0 12e1 2d41  ..........N...-A
0x7ffd70c20ea5  5600 004a ee3b 8fdf 7f00 0098 0fc2 70fd  V..J.;........p.
0x7ffd70c20eb5  7f00 007f ec3b 8f01 0000 0065 11e1 2d41  .....;.....e..-A
0x7ffd70c20ec5  5600 0000 0000 0008 0000 0000 0000 0000  V...............
0x7ffd70c20ed5  0000 008c c84a 5f97 a5a4 6b80 10e1 2d41  .....J_...k...-A
0x7ffd70c20ee5  5600 0000 0000 0000 0000 0000 0000 0000  V...............
0x7ffd70c20ef5  0000 0000 0000 0000 0000 008c c86a 67d1  .............jg.
0x7ffd70c20f05  1fdc 388c c80c a622 e099 3800 0000 0000  ..8...."..8.....
0x7ffd70c20f15  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffd70c20f25  0000 0001 0000 0000 0000 0098 0fc2 70fd  ..............p.
0x7ffd70c20f35  7f00 00a8 0fc2 70fd 7f00 00e0 415a 8fdf  ......p.....AZ..
0x7ffd70c20f45  7f00 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffd70c20f55  0000 0080 10e1 2d41 5600 0090 0fc2 70fd  ......-AV.....p.
```

An there it is that 'Demon name', `Adrammelech`.

## Give me the flag!

To get the flag just use `Adrammelech` as the answer to the program question:
```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ ./demon            

Luciafer v1.0
Say the demon's name to gain access to the secret.
Enter the demon's name: Adrammelech

You are correct.
flag{AdraMMel3ch}
```
