---
description: esab64 Nahamcon 2021 challenge write up.
---

# esab64

The challenges gives a file called `esab64` with an encoded message. The first thing i though was trying to decode the message with base64. The thing is that the result was not... something clear. After a while, an idea came to my mind: esab64 looks like base64 but in reverse so... why not trying to reverse the initial message and then decode it with base64. My idea seems to have worked:

```
_}e61e711106bd0db1b78efa894b1125bf{galf
```

I just had to reverse that message again to get the flag:

```
flag{fb5211b498afe87b1bd0db601117e16e}_
```
