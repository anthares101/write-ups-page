---
title: File 101
description: File 101 DEADFACE CTF 2021 challenge write up.
---

# File 101 <a href='/assets/resources/CTFs/DEADFACE_CTF_2021/File101-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## All started with an image

The challenge gives an image to start with. Searching in it we found a trailing string that was a link to a file in dropbox.

## A protected zip file

The file we got from that dropbox link is a protected zip. After a while we decided to throw John the ripper with the Rockyou dictionary and it worked! Now we have a corrupted file, let's continue.

### Fixing things up

Looking at the file magic bits we can see that is probably a jpeg image. Fixing the header allow us to open the image and get the flag:

```
flag{Easy_Right}
```
