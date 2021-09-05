---
title: MeetTheTeam
description: MeetTheTeam Nahamcon 2021 challenge write up.
---

# MeetTheTeam <a href='/assets/resources/CTFs/Nahamcon_2021/MeetTheTeam-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

Looks like the page has actually the version control software public:

```
https://constellations.page/.git/
```

Using a script called `gitdumper.sh` from [GitTools](https://github.com/internetwache/GitTools) i could extract it. Using `git show` and checking the changes i found the flag:

```
flag{4063962f3a52f923ddb4411c139dd24c}
```
