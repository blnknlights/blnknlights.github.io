## Enum
```bash
nmap -sC -sV 10.10.11.210 -oN scans/nmap.initial
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-23 19:21 IST
Nmap scan report for only4you.htb (10.10.11.210)
Host is up (0.036s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
|   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
|_  256 445f7aa377690a77789b04e09f11db80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Only4you
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.05 seconds
```

```bash
dirsearch -r -u http://only4you.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/only4you.htb/_23-05-23_19-23-24.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-05-23_19-23-24.log

Target: http://only4you.htb/

[19:23:24] Starting:

Task Completed
```

```bash
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u "http://only4you.htb" \
  -H "Host: FUZZ.only4you.htb" -mc all -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://only4you.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.only4you.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

[Status: 200, Size: 2191, Words: 370, Lines: 52, Duration: 36ms]
    * FUZZ: beta

:: Progress: [114441/114441] :: Job [1/1] :: 1234 req/sec :: Duration: [0:01:36] :: Errors: 0 ::
```

```bash
dirsearch -r -u http://beta.only4you.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/beta.only4you.htb/_23-05-23_19-27-28.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-05-23_19-27-28.log

Target: http://beta.only4you.htb/

[19:27:28] Starting:
[19:27:40] 405 -  683B  - /download
[19:27:43] 200 -    6KB - /list
[19:27:49] 200 -   12KB - /source

Task Completed
```

```bash
curl -I -XGET http://beta.only4you.htb/download
HTTP/1.1 405 METHOD NOT ALLOWED
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 23 May 2023 18:29:36 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 683
Connection: keep-alive
```
```bash
curl -I -XPOST http://beta.only4you.htb/download
HTTP/1.1 400 BAD REQUEST
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 23 May 2023 18:29:41 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 676
Connection: keep-alive
```

```bash
grep route app.py
@app.route('/', methods=['GET'])
@app.route('/resize', methods=['POST', 'GET'])
@app.route('/convert', methods=['POST', 'GET'])
@app.route('/source')
@app.route('/list', methods=['GET'])
@app.route('/download', methods=['POST'])
```

