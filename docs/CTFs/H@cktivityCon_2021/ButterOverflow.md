---
title: ButterOverflow
description: ButterOverflow H@cktivityCon 2021 challenge write up.
---

# ButterOverflow <a href='/assets/resources/CTFs/H@cktivityCon_2021/ButterOverflow-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

Checking the code we can see that if the a buffer overflow exception occur the program will print the flag. Since the buffer allocated is 512 bytes long and is using the `gets` function to get the data for it we can easily insert for example 600 bytes and get the flag:

```flag{72d8784a5da3a8f56d2106c12dbab989}```
