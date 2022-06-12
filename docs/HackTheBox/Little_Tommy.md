---
title: Little Tommy
description: Little Tommy challenge from HackTheBox write up.
---

# Little Tommy <a href='/assets/resources/HackTheBox/LittleTommy-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## What it does?

 The program is basically a simple bank account system:

```bash
#################### Welcome to Little Tommy's Handy yet Elegant and Advanced Program ####################

1. Create account
2. Display account
3. Delete account
4. Add memo
5. Print flag

Please enter an operation number:
```

The `Print flag` option obviously returns a NOPE, so let's start searching for something to make its opinion change.

## Checksec

First we can check the binary security:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Little Tommy]
└─$ checksec little_tommy
[*] '/home/kali/Desktop/HTB/Little Tommy/little_tommy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We see that it has no PIE, what can be useful. Next step is to open Ghidra and check the code.

## Digging

The program code is this according to Ghidra:

```c
void main(void)

{
  int iVar1;
  int iVar2;
  size_t sVar3;
  int in_GS_OFFSET;
  char local_114 [256];
  undefined4 local_14;
  undefined *puStack16;
  
  puStack16 = &stack0x00000004;
  local_14 = *(undefined4 *)(in_GS_OFFSET + 0x14);
  puts(
      "\n#################### Welcome to Little Tommy\'s Handy yet Elegant and Advanced Program ####################"
      );
  do {
    printf(
          "\n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: "
          );
    iVar1 = getchar();
    do {
      iVar2 = getchar();
      if ((char)iVar2 == '\n') break;
    } while ((char)iVar2 != -1);
    switch((char)iVar1) {
    case '1':
      main_account = (char *)malloc(0x48);
      printf("\nFirst name: ");
      fgets(local_114,0x100,stdin);
      strncpy(main_account,local_114,0x1e);
      sVar3 = strlen(main_account);
      if ((int)sVar3 < 0x1f) {
        main_account[sVar3 - 1] = '\0';
      }
      else {
        main_account[0x1f] = '\0';
      }
      printf("Last name: ");
      fgets(local_114,0x100,stdin);
      strncpy(main_account + 0x20,local_114,0x1e);
      sVar3 = strlen(main_account + 0x20);
      if ((int)sVar3 < 0x1f) {
        main_account[sVar3 + 0x1f] = '\0';
      }
      else {
        main_account[0x3f] = '\0';
      }
      printf("\nThank you, your account number %d.\n",main_account);
      break;
    case '2':
      if (main_account == (char *)0x0) {
        puts("\nSorry, no account found.");
      }
      else {
        printf("\n################ Account no. %d ################\nFirst name: %s\nLast name: %s\nAccount balance: %d\n\n"
               ,main_account,main_account,main_account + 0x20,*(undefined4 *)(main_account + 0x40));
      }
      break;
    case '3':
      if (main_account == (char *)0x0) {
        puts("\nSorry, no account found.");
      }
      else {
        free(main_account);
        puts("\nAccount deleted successfully");
      }
      break;
    case '4':
      puts("\nPlease enter memo:");
      fgets(local_114,0x100,stdin);
      memo = strdup(local_114);
      printf("\nThank you, please keep this reference number number safe: %d.\n",memo);
      break;
    case '5':
      if ((main_account == (char *)0x0) || (*(int *)(main_account + 0x40) != 0x6b637566)) {
        puts("\nNope.");
      }
      else {
        system("/bin/cat flag");
      }
    }
  } while( true );
}
```

Looking around, looks like the flag option only will print the flag if the content of `main_account[64]` is `0x6b637566`.  That value transformed to string is basically the string `f**k` (Yep I redacted that, all of you know the word) and according to the code that shows the account information, it represents the account balance.

The `Add memo` option asks for a string and reserve memory for it using again `malloc`.

The `main_account` buffer is 72 character long and is reserved using `malloc`. We can easily see that the `Delete account` option just free that memory, the thing is that the pointer is not reset so the program is still accessing that part of the memory to read information from.

The `Add memo` option also reserve memory with `malloc` which is perfect for us in this situation. `malloc` will try to reuse a previous memory area that was free'd if the size of it is more or less the same that the memory we need to allocate. This means that if we create and delete an account we can use the `Add memo` option to allocate again the memory that once belonged to the `main_account` buffer and write to it whatever we want. Since the pointer of `main_account` was not reseted, the `Print flag` option will evaluate the memory area we control.

## Exploit time!

To exploit the vulnerability we discovered, first we need to create an account and delete it, then we have to write a 64 bytes long string followed by the magic word `f**k` to the buffer created by the `Add memo` option. Our payload will be injected in the same memory area where the `main_account` was allocated so since we now fulfill the requirements we can ask for the flag!
