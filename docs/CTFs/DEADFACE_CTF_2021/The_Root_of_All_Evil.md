---
title: The Root of All Evil
description: The Root of All Evil DEADFACE CTF 2021 challenge write up.
---

# The Root of All Evil <a href='/assets/resources/CTFs/DEADFACE_CTF_2021/TheRootOfAllEvil-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## First things first...

I tried to connect to the host but it just rejected the conection asking for a private key. 

## Getting access

The challenge gives a `pcap` file to use so I guess that somewhere in there should be a private key. Searching in the `pcap` file for the string `private` in the packets data part revealed the Luciafer private key!

## Give me my flag!

We can now connect to the machine and get the flag under `/home/luciafer/Downloads/flag.txt`:

```
flag{Lucy-a-FUR-G0T-R3KT-by-the-BLUZers-CLUB!!!}
```
