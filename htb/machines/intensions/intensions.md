## Enum

```bash
nmap -Pn -sC -sV 10.10.11.220 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-15 18:31 IST
Nmap scan report for 10.10.11.220
Host is up (0.034s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47:d2:00:66:27:5e:e6:9c:80:89:03:b5:8f:9e:60:e5 (ECDSA)
|_  256 c8:d0:ac:8d:29:9b:87:40:5f:1b:b0:a4:1d:53:8f:f1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Intentions
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.88 seconds
```

```bash
curl -I http://10.10.11.220
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Cache-Control: no-cache, private
Date: Tue, 15 Aug 2023 17:32:36 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6IlFxUm81V2IyQ01MaFZQcVpxYmpKTEE9PSIsInZhbHVlIjoiTGpXNGZxb1loWjVwZDZiTWRqSGlJMTJ3MzVxbnlLSmsxRk5lcUhJd1BhUStTeElBUXV0WHlJd210dXB2Z3dUSXZIK1F1dmRtakNZQzVPMUI2RStLbGJSVjFuYVIyc1ZVQmVReGI2WktNZnFMaUVDc2YzQ0FTL3dnVTBvWWNUQ1MiLCJtYWMiOiI3ZDc1YzBkOGQ4MzNjM2ZiMjg3Njg5NjRlMTBjZjg3MWJmZjliNzUzZjE2ZmU1MTBiYTg2MjI2YThmYThkNWY1IiwidGFnIjoiIn0%3D; expires=Tue, 15-Aug-2023 19:32:36 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: intentions_session=eyJpdiI6InJnYmR0YXplYncyQTFDeDVSdllNVmc9PSIsInZhbHVlIjoiZzZXMXQ2ajFWUi90b1ZtaXZPS2JzMll5RjU4UDVPbW1TRUx4WHczSWd1elh1c3NiM2xKVVVzMG51Tm9YSjZySFgzd0Fkb2pveWVXNjFKWFUwVmRnRytqS2pBTWtpcUxtYzQ1WDFKOW1uWnl2OEwvNnNFU1hENFhiL3JQaFdhK28iLCJtYWMiOiI2ZWExNTE3NWIzYzIzYzc0ZGZiNDkwYjA4NjkwYWE1YjNjNTU2MDJlMjA5Mzk3YzI4YmFlYzM3OTExNGNhNzYzIiwidGFnIjoiIn0%3D; expires=Tue, 15-Aug-2023 19:32:36 GMT; Max-Age=7200; path=/; httponly; samesite=lax
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
```

![register.png](register.png)  

```
Cookie: 

token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNjkyMTIxOTQwLCJleHAiOjE2OTIxNDM1NDAsIm5iZiI6MTY5MjEyMTk0MCwianRpIjoiU2hzTXVLVUF1RGdJaXd0eCIsInN1YiI6IjI4IiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.TIybgtDf4_nYKSpfzpBAa8ix4dfdYyWUo11aB73YYMo;

{
  "iss": "http://10.10.11.220/api/v1/auth/login",
  "iat": 1692121940,
  "exp": 1692143540,
  "nbf": 1692121940,
  "jti": "ShsMuKUAuDgIiwtx",
  "sub": "28",
  "prv": "23bd5c8949f600adb39e701c400872db7a5976f7"
}

XSRF-TOKEN=eyJpdiI6IllpZDVSMENGMmZTTlBIK3FMbytMYkE9PSIsInZhbHVlIjoiNTNEQXE0ajZENThETlFQR2RKY2QwUFYvcmVMaHh3dnkwV0NGTTdlbSs2Tm9ha0h2cndjNE5xUGZHVmF4UnRmNVFGQS9sL0RWOWdKT2Y3Z25ZeVRMWmNDL1ZyTU9mQTRVRnNmNzZkcXY5MzIwMmlEYzNJQXJ6MU82b29HN1NxeUUiLCJtYWMiOiJmOTc4MDVmNGFjZWVjMTZmZmVjYWQ2NmZiYzRlZmI1NWY0MjVmODRiOTNhY2RhNjM4YmE4NDEwMGE5YWQ1ODMyIiwidGFnIjoiIn0%3D;

{
  "iv": "Yid5R0CF2fSNPH+qLo+LbA==",
  "value": "53DAq4j6D58DNQPGdJcd0PV/reLhxwvy0WCFM7em+6NoakHvrwc4NqPfGVaxRtf5QFA/l/DV9gJOf7gnYyTLZcC/VrMOfA4UFsf76dqv93202iDc3IArz1O6ooG7SqyE",
  "mac": "f97805f4aceec16ffecad66fbc4efb55f425f84b93acda638ba84100a9ad5832",
  "tag": ""
}

intentions_session=eyJpdiI6IndQTlhINFRya0szdEdiNlM5Tk4yNlE9PSIsInZhbHVlIjoiejRHblJnS1F1ci9FbmFMRHQzYytlRmpXN2wyTlJ6aHVNOFFicHhrSkpyMVFlY1BERFhHZ0c1Zlh0YlFJV3diQm9YYXdOZFRaV1lXa0ZNdjZWYURsRmNGSXQ4UFFYNjM5TVIzY0ZRUWZ6a3lMcGpVOHkvZmN3SU5Wd1lWczVXTXoiLCJtYWMiOiJkNDJlMzVkNWVhNmIxMjEwMGIyOTg0ZDQzMTAzZWE2MTQ4YjgyZDE0ZWIxYWQyNjc4OGE5ZjZjYzE4YzRkNzJjIiwidGFnIjoiIn0%3D

{
  "iv": "wPNXH4TrkK3tGb6S9NN26Q==",
  "value": "z4GnRgKQur/EnaLDt3c+eFjW7l2NRzhuM8QbpxkJJr1QecPDDXGgG5fXtbQIWwbBoXawNdTZWYWkFMv6VaDlFcFIt8PQX639MR3cFQQfzkyLpjU8y/fcwINVwYVs5WMz",
  "mac": "d42e35d5ea6b12100b2984d43103ea6148b82d14eb1ad26788a9f6cc18c4d72c",
  "tag": ""
}

```

![jwt.png](jwt.png)  

```bash
ffuf \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u "http://10.10.11.220/FUZZ" \
  -mc all -fs 6609

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.220/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 6609
________________________________________________

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 36ms]
    * FUZZ: css

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 37ms]
    * FUZZ: js

[Status: 302, Size: 322, Words: 60, Lines: 12, Duration: 70ms]
    * FUZZ: admin

[Status: 302, Size: 322, Words: 60, Lines: 12, Duration: 157ms]
    * FUZZ: logout

[Status: 302, Size: 322, Words: 60, Lines: 12, Duration: 85ms]
    * FUZZ: gallery

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 41ms]
    * FUZZ: fonts

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 42ms]
    * FUZZ: storage

[Status: 200, Size: 1523, Words: 415, Lines: 40, Duration: 285ms]
    * FUZZ:

:: Progress: [30000/30000] :: Job [1/1] :: 139 req/sec :: Duration: [0:03:35] :: Errors: 2 ::
```
```bash
ffuf \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -u "http://10.10.11.220/FUZZ" \
  -mc all -fs 6609,16,162

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.220/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 6609,16,162
________________________________________________

[Status: 200, Size: 1523, Words: 415, Lines: 40, Duration: 120ms]
    * FUZZ: index.php

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 35ms]
    * FUZZ: favicon.ico

[Status: 200, Size: 24, Words: 2, Lines: 3, Duration: 58ms]
    * FUZZ: robots.txt

:: Progress: [17129/17129] :: Job [1/1] :: 198 req/sec :: Duration: [0:02:13] :: Errors: 0 ::
```
```bash
ffuf \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u "http://10.10.11.220/js/FUZZ" \
  -X POST -mc all -fs 6609,16,162 -e .js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.11.220/js/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Extensions       : .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 6609,16,162
________________________________________________

[Status: 405, Size: 166, Words: 6, Lines: 8, Duration: 35ms]
    * FUZZ: admin.js

[Status: 405, Size: 166, Words: 6, Lines: 8, Duration: 27ms]
    * FUZZ: login.js

[Status: 405, Size: 166, Words: 6, Lines: 8, Duration: 29ms]
    * FUZZ: app.js

[Status: 405, Size: 166, Words: 6, Lines: 8, Duration: 32ms]
    * FUZZ: gallery.js

[WARN] Caught keyboard interrupt (Ctrl-C)
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```

